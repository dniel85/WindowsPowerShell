# SQL Initialization...
if ([enum]::getvalues([System.Management.Automation.ActionPreference]) -contains 'ignore') {
    $ea_ignore = [System.Management.Automation.ActionPreference]::Ignore
}
else {
    $ea_ignore = [System.Management.Automation.ActionPreference]::SilentlyContinue
}

Function Get-SupportedProducts {
    Param (
        [Parameter(Mandatory = $true)]
        [String] $ES_Path
    )

    [XML]$STIGList = Get-Content (Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "STIGList.xml")
    $OutList = New-Object System.Collections.Generic.List[System.Object]
    ForEach ($Node in $STIGList.List.STIG) {
        If (-Not(Test-Path (Join-Path -Path $ES_Path -ChildPath "CKLTemplates" | Join-Path -ChildPath $Node.Template))) {
            $STIGVersion = "Template missing"
        }
        Else {
            $CKLTemplate = (Join-Path -Path $ES_Path -ChildPath "CKLTemplates" | Join-Path -ChildPath $Node.Template)
            $CKLContent = Select-Xml -Path $CKLTemplate -XPath "CHECKLIST/STIGS/iSTIG/STIG_INFO/SI_DATA"
            $attVersion = ($CKLContent.Node | Where-Object SID_NAME -EQ "version").SID_DATA
            $attRelease = (($CKLContent.Node | Where-Object SID_NAME -EQ "releaseinfo").SID_DATA -split " ")[1]
            $STIGVersion = "V$($attVersion)R$($attRelease)"
        }

        $NewObj = [PSCustomObject]@{
            Name      = $Node.Name
            Shortname = $Node.ShortName
            Version   = $STIGVersion
            Template  = $Node.Template
        }
        $OutList.Add($NewObj)
    }
    Return $OutList
}

Function Get-ApplicableProducts {
    Param (
        [Parameter(Mandatory = $true)]
        [String] $ES_Path
    )

    [XML]$STIGList = Get-Content (Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "STIGList.xml")
    $OutList = New-Object System.Collections.Generic.List[System.Object]

    $ProgressId = 1
    $ProgressActivity = "Checking STIG applicability..."
    $TotalSteps = ($STIGList.List.STIG).Count
    $CurrentStep = 1
    ForEach ($Node in $STIGList.List.STIG) {
        Write-Progress -Id 1 -Activity $ProgressActivity -Status $Node.Name -PercentComplete ($CurrentStep / $TotalSteps * 100)
        $CurrentStep++
        If ($Node.DetectionCode -and (Invoke-Expression $Node.DetectionCode) -eq $true) {
            If (-Not(Test-Path (Join-Path -Path $ES_Path -ChildPath "CKLTemplates\$($Node.Template)"))) {
                $STIGVersion = "Template missing"
            }
            Else {
                $CKLTemplate = (Join-Path -Path $ES_Path -ChildPath "CKLTemplates\$($Node.Template)")
                $CKLContent = Select-Xml -Path $CKLTemplate -XPath "CHECKLIST/STIGS/iSTIG/STIG_INFO/SI_DATA"
                $attVersion = ($CKLContent.Node | Where-Object SID_NAME -EQ "version").SID_DATA
                $attRelease = (($CKLContent.Node | Where-Object SID_NAME -EQ "releaseinfo").SID_DATA -split " ")[1]
                $STIGVersion = "V$($attVersion)R$($attRelease)"
            }

            $NewObj = [PSCustomObject]@{
                Name      = $Node.Name
                Shortname = $Node.ShortName
                Version   = $STIGVersion
                Template  = $Node.Template
            }
            $OutList.Add($NewObj)
        }
    }
    Write-Progress -Id $ProgressId -Activity $ProgressActivity -Completed
    Return $OutList
}

Function Invoke-RemoteScan {
    Param (
        # Evaluate-STIG parameters
        [Parameter(Mandatory = $true)]
        [String[]]$ComputerName,

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
        [Switch]$GenerateOQE,

        [Parameter(Mandatory = $false)]
        [Switch]$NoPrevious,

        [Parameter(Mandatory = $false)]
        [Switch]$ApplyTattoo,

        [Parameter(Mandatory = $false)]
        [Array]$SelectSTIG,

        [Parameter(Mandatory = $false)]
        [Array]$SelectVuln,

        [Parameter(Mandatory = $false)]
        [Array]$ExcludeVuln,

        [Parameter(Mandatory = $false)]
        [Array]$ExcludeSTIG,

        [Parameter(Mandatory = $false)]
        [Switch]$AltCredential,

        [Parameter(Mandatory = $false)]
        [Int]$ThrottleLimit = 10,

        # Remote scan parameters
        [Parameter(Mandatory = $true)]
        [String]$ESVersion,

        [Parameter(Mandatory = $true)]
        [String]$LogComponent,

        [Parameter(Mandatory = $true)]
        [String]$OSPlatform,

        [Parameter(Mandatory = $true)]
        [String] $ES_Path,

        [Parameter(Mandatory = $true)]
        [String] $RemoteScanDir,

        [Parameter(Mandatory = $true)]
        [String] $RemoteWorkingDir,

        [Parameter(Mandatory = $true)]
        [String] $PowerShellVersion
    )

    Try {
        $StartTime = Get-Date

        # Reconstruct command line for logging purposes
        $ParamsNotForLog = @("ESVersion", "LogComponent", "OSPlatform", "ES_Path", "PowerShellVersion") # Parameters not be be written to log
        $BoundParams = $PSBoundParameters # Collect called parameters
        ForEach ($Item in $ParamsNotForLog) {
            # Remove parameter from collection so that it will not be logged
            $BoundParams.Remove($Item) | Out-Null
        }
        $CommandLine = "Evaluate-STIG.ps1"
        ForEach ($Item in $BoundParams.Keys) {
            Switch ($BoundParams.$Item.GetType().Name) {
                { ($_ -in @("String[]", "Object[]")) } {
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

        $STIGLog_Remote = Join-Path -Path $RemoteScanDir -ChildPath "Evaluate-STIG_Remote.log"
        If (Test-Path $STIGLog_Remote) {
            Remove-Item $STIGLog_Remote -Force
        }

        # Begin logging
        Write-Log $STIGLog_Remote "Executing: $($CommandLine)" $LogComponent "Info" -OSPlatform $OSPlatform
        Write-Log $STIGLog_Remote "----------------------------------" $LogComponent "Info" -OSPlatform $OSPlatform
        If (-NOT([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Log $STIGLog_Remote "Executing Evaluate-STIG without local administrative rights." $LogComponent "Warning" -OSPlatform $OSPlatform
        }
        Write-Log $STIGLog_Remote "Evaluate-STIG Version: $($ESVersion)" $LogComponent "Info" -OSPlatform $OSPlatform

        # Verify required Evaluate-STIG files exist and their integrity
        $Verified = $true
        Write-Log $STIGLog_Remote "Verifying Evaluate-STIG file integrity..." $LogComponent "Info" -OSPlatform $OSPlatform
        If (Test-Path (Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "FileList.xml")) {
            [XML]$FileListXML = Get-Content -Path (Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "FileList.xml")
            If ((Test-XmlSignature -checkxml $FileListXML -Force) -ne $true) {
                Write-Log $STIGLog_Remote "'FileList.xml' failed authenticity check.  Unable to verify content integrity." $LogComponent "Error" -OSPlatform $OSPlatform
                Write-Host "ERROR: 'FileList.xml' failed authenticity check.  Unable to verify content integrity." -ForegroundColor Red
                ForEach ($File in $FileListXML.FileList.File) {
                    If ($File.ScanReq -eq "Required") {
                        Write-Log $STIGLog_Remote "'$($File.Name)' is a required file but not found.  Scan results may be incomplete." $LogComponent "Error" -OSPlatform $OSPlatform
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
                            Write-Log $STIGLog_Remote "'$($Path)' failed integrity check." $LogComponent "Warning" -OSPlatform $OSPlatform
                        }
                    }
                    Else {
                        If ($File.ScanReq -eq "Required") {
                            $Verified = $false
                            Write-Log $STIGLog_Remote "'$($File.Name)' is a required file but not found.  Scan results may be incomplete." $LogComponent "Error" -OSPlatform $OSPlatform
                            Write-Host "'$($File.Name)' is a required file but not found.  Scan results may be incomplete." -ForegroundColor Red
                        }
                    }
                }
                If ($Verified -eq $true) {
                    Write-Log $STIGLog_Remote "Evaluate-STIG file integrity check passed." $LogComponent "Info" -OSPlatform $OSPlatform
                }
                Else {
                    Write-Host "WARNING: One or more Evaluate-STIG files failed integrity check." -ForegroundColor Yellow
                }
            }
        }
        Else {
            Write-Log $STIGLog_Remote "'FileList.xml' not found.  Cannot continue." $LogComponent "Error" -OSPlatform $OSPlatform
            Write-Host "ERROR: 'FileList.xml' not found.  Cannot continue." -ForegroundColor Red -BackgroundColor Black
            Exit 2
        }

        # For remote scans, archive Evaluate-STIG files and, if necessary, answer files for faster transport to remote machines
        # Clean up orphaned archives
        If (Test-Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp")) {
            Write-Log $STIGLog_Remote "Removing orphaned folder: $(Join-Path -Path $RemoteWorkingDir -ChildPath 'Evaluate-STIG_tmp')" $LogComponent "Info" -OSPlatform $OSPlatform
            Remove-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp") -Recurse -Force
        }
        If (Test-Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "ESCONTENT.ZIP")) {
            Write-Log $STIGLog_Remote "Removing orphaned file: $(Join-Path -Path $RemoteWorkingDir -ChildPath 'ESCONTENT.ZIP')" $LogComponent "Info" -OSPlatform $OSPlatform
            Remove-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "ESCONTENT.ZIP") -Force
        }
        If (Test-Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "AFILES.ZIP")) {
            Write-Log $STIGLog_Remote "Removing orphaned file: $(Join-Path -Path $RemoteWorkingDir -ChildPath 'AFILES.ZIP')" $LogComponent "Info" -OSPlatform $OSPlatform
            Remove-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "AFILES.ZIP") -Force
        }

        # Copy files needed for scan to Evaluate-STIG_tmp
        # FileList.xml
        If (-Not(Test-Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath "xml"))) {
            $null = New-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath "xml") -ItemType Directory -ErrorAction Stop
        }
        Copy-Item -Path $(Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "FileList.xml") -Destination $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath "xml") -Force -ErrorAction Stop
        # Files marked "Required" and "Optional"
        ForEach ($File in ($FileListXML.FileList.File | Where-Object ScanReq -In @("Required", "Optional"))) {
            If (Test-Path $(Join-Path -Path $ES_Path -ChildPath $File.Path | Join-Path -ChildPath $File.Name)) {
                If (-Not(Test-Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath $File.Path))) {
                    $null = New-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath $File.Path) -ItemType Directory -ErrorAction Stop
                }
                $tmpSource = (Join-Path -Path $ES_Path -ChildPath $File.Path | Join-Path -ChildPath $File.Name)
                $tmpDest = (Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath $File.Path | Join-Path -ChildPath $File.Name)
                Copy-Item -Path  $tmpSource -Destination $tmpDest -Force -ErrorAction Stop
            }
        }

        # Copy default answer file location
        $null = New-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath "AnswerFiles") -ItemType Directory -ErrorAction Stop
        If (Test-Path $(Join-Path -Path $ES_Path -ChildPath "AnswerFiles")) {
            Get-ChildItem -Path $(Join-Path -Path $ES_Path -ChildPath "AnswerFiles") | Where-Object Extension -EQ ".xml" | Copy-Item -Destination $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath "AnswerFiles") -Force -ErrorAction Stop
        }

        # Create archive of Evaluate-STIG core files
        If (-Not(Test-Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "ESCONTENT.ZIP"))) {
            Write-Host "Prepping files for remote scan..."
            Write-Host " - Compressing Evaluate-STIG files"
            Write-Log $STIGLog_Remote "Prepping files for remote scan..." $LogComponent "Info" -OSPlatform $OSPlatform
            Write-Log $STIGLog_Remote "Compressing Evaluate-STIG files" $LogComponent "Info" -OSPlatform $OSPlatform
            $Result = Initialize-Archiving -Action Compress -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath "*") -Destination $(Join-Path -Path $RemoteWorkingDir -ChildPath "ESCONTENT.ZIP") -CompressionLevel Optimal
            If ($Result -ne "Success") {
                Throw $Result
            }
            Remove-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp") -Recurse -Force
        }

        # Create archive of Answer Files if not in default path (Evaluate-STIG\AnswerFiles)
        If (($AFPath.TrimEnd('\')).TrimEnd('/') -ne (Join-Path -Path $ES_Path -ChildPath "AnswerFiles")) {
            If (-Not(Test-Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "AFILES.ZIP"))) {
                Write-Host " - Compressing answer files from $AFPath"
                Write-Log $STIGLog_Remote "Compressing answer files from $AFPath" $LogComponent "Info" -OSPlatform $OSPlatform
                $Result = Get-ChildItem -Path $AFPath | Where-Object Extension -EQ ".xml" | ForEach-Object { Initialize-Archiving -Action Compress -Path $($_.FullName) -DestinationPath $(Join-Path -Path $RemoteWorkingDir -ChildPath "AFILES.ZIP") -Update -CompressionLevel Optimal }
                If ($Result -ne "Success") {
                    Throw $Result
                }
            }
        }

        # Build the list of computers, if necessary.
        $LocalHost = New-Object System.Collections.Generic.List[System.Object]
        $ComputerTempList = New-Object System.Collections.Generic.List[System.Object]
        $ComputerList = New-Object System.Collections.Generic.List[System.Object]
        $WindowsList = New-Object System.Collections.Generic.List[System.Object]
        $LinuxList = New-Object System.Collections.Generic.List[System.Object]
        $OfflineList = New-Object System.Collections.Generic.List[System.Object]
        $RemoteUnresolveCount = 0

        # Get local host data
        $NewObj = [PSCustomObject]@{
            HostName    = ([Environment]::MachineName).ToUpper()
            IPv4Address = (Get-NetIPAddress).IPv4Address
        }
        $LocalHost.Add($NewObj)

        # Put all ComputerName items into a temp list for resolving

        ForEach ($Item in ($ComputerName -split ',(?=(?:[^"]|"[^"]*")*$)')) { #convert string to array, comma delimiter.  if path has comma, it must be enclosed in double quotes
            If (Test-Path $Item -PathType Leaf) {
                Get-Content $Item | ForEach-Object {
                    If ($_ -ne $null) {
                        $ComputerTempList.Add($_)
                    }
                }
                Continue
            }
            If ($Item -is [array]) {
                $Item | ForEach-Object {
                    $ComputerTempList.Add($_)
                }
            }
            Else {
                $ComputerTempList.Add($Item)
            }
        }

        # Get NETBIOS and FQDN of each computer
        Foreach ($Computer in ($ComputerTempList)) {
            If (($Computer -eq "127.0.0.1") -or ($Computer -eq "::1") -or ($Computer -eq "localhost") -or ($Computer.Split('.')[0] -eq $LocalHost.HostName) -or ($Computer -in $LocalHost.IPv4Address)) {
                $NewObj = [PSCustomObject]@{
                    NETBIOS = $LocalHost.HostName
                    FQDN    = "LOCALHOST"
                }
                $ComputerList.Add($NewObj)
            }
            Else {
                # Resolve Computer
                Try {
                    $FQDN = ([Net.DNS]::GetHostEntry($Computer).Hostname).ToUpper()
                    $NewObj = [PSCustomObject]@{
                        NETBIOS = $FQDN.Split('.')[0]
                        FQDN    = $FQDN
                    }
                    $ComputerList.Add($NewObj)
                }
                Catch {
                    Write-Host "Unable to resolve $Computer" -ForegroundColor Red
                    $OfflineList.Add($Computer)
                    $RemoteUnresolveCount++
                    Write-Log $STIGLog_Remote "Unable to resolve $Computer" $LogComponent "Error" -OSPlatform $OSPlatform
                }
            }
        }
        Remove-Variable ComputerTempList
        [System.GC]::Collect()
        $ComputerList = $ComputerList | Sort-Object NETBIOS -Unique

        $ConnectionScriptBlock = {
            Param (
                [String]$NETBIOS,
                [String]$FQDN
            )
            $tcp = New-Object Net.Sockets.TcpClient
            Try {
                $tcp.Connect($FQDN, 5986)
            }
            catch {
            }

            if ($tcp.Connected) {
                $Connection = "5986"
            }
            else {
                Try {
                    $tcp.Connect($FQDN, 5985)
                }
                catch {
                }

                if ($tcp.Connected) {
                    $Connection = "5985"
                }
                else {
                    Try {
                        $tcp.Connect($FQDN, 22)
                    }
                    catch {
                    }

                    if ($tcp.Connected) {
                        $Connection = "22"
                    }
                }
            }

            $tcp.close()

            [PSCustomObject]@{
                NETBIOS   = $NETBIOS
                FQDN      = $FQDN
                Connected = $Connection
            }
        }

        $ConnectionRunspacePool = [RunspaceFactory]::CreateRunspacePool(1, 10)
        $ConnectionRunspacePool.Open()

        $ProgressSpinner = @("|", "/", "-", "\")
        $ProgressSpinnerPos = 0
        $ConnectionJobs = New-Object System.Collections.ArrayList

        $ComputerList | ForEach-Object {
            $ParamList = @{
                NETBIOS = $_.NETBIOS
                FQDN    = $_.FQDN
            }
            $ConnectionJob = [powershell]::Create().AddScript($ConnectionScriptBlock).AddParameters($ParamList)
            $ConnectionJob.RunspacePool = $ConnectionRunspacePool

            $null = $ConnectionJobs.Add([PSCustomObject]@{
                    Pipe   = $ConnectionJob
                    Result = $ConnectionJob.BeginInvoke()
                })
        }
        Write-Host ""

        Write-Log $STIGLog_Remote "Generating list of scannable hosts..." $LogComponent "Info" -OSPlatform $OSPlatform
        Do {
            Write-Host "`rGenerating list of scannable hosts.  Attempting connection to $(($ConnectionJobs.Result.IsCompleted | Measure-Object).Count) hosts. $($ProgressSpinner[$ProgressSpinnerPos])" -NoNewline
            $ProgressSpinnerPos++
            Start-Sleep -Seconds 1
            if ($ProgressSpinnerPos -ge $ProgressSpinner.Length) {
                $ProgressSpinnerPos = 0
            }
        } While ( $ConnectionJobs.Result.IsCompleted -contains $false)

        $ConnectionResults = $(ForEach ($ConnectionJob in $ConnectionJobs) {
                $ConnectionJob.Pipe.EndInvoke($ConnectionJob.Result)
            })

        $ConnectionRunspacePool.Close()
        $ConnectionRunspacePool.Dispose()

        $ConnectionResults | ForEach-Object {
            if ($_.Connected -eq "5986") {
                $WindowsList.Add($_)
            }
            elseif ($_.Connected -eq "5985") {
                $WindowsList.Add($_)
            }
            elseif ($_.Connected -eq "22") {
                $LinuxList.Add($_)
            }
            else {
                $OfflineList.Add($_.NETBIOS)
            }
        }
        if ((($WindowsList | Measure-Object).count + ($LinuxList | Measure-Object).count) -eq 0) {
            Write-Log $STIGLog_Remote "No valid remote hosts found." $LogComponent "Error" -OSPlatform $OSPlatform
            Write-Host " - No valid remote hosts found." -ForegroundColor Red
        }
        else {
            Write-Host "`rGenerating list of scannable machines.  Connected to $(($WindowsList | Measure-Object).count + ($LinuxList | Measure-Object).count) hosts. $(($WindowsList | Measure-Object).count) Windows and $(($LinuxList | Measure-Object).count) Linux" -NoNewline
            Write-Log $STIGLog_Remote "Connected to $(($WindowsList | Measure-Object).count + ($LinuxList | Measure-Object).count) hosts. $(($WindowsList | Measure-Object).count) Windows and $(($LinuxList | Measure-Object).count) Linux" $LogComponent "Info" -OSPlatform $OSPlatform
            Write-Host ""
        }

        # Prompt for AltCredential
        If ($AltCredential -and (($WindowsList | Measure-Object).count -gt 0)) {
            $Credentialcreds = Get-Creds
        }

        $RemoteScriptBlock = {
            Param(
                $ConnectionResult,
                $STIGLog_Remote,
                $LogComponent,
                $OSPlatform,
                $RemoteWorkingDir,
                $ScanType,
                $Marking,
                $VulnTimeout,
                $AnswerKey,
                $OutputPath,
                $AltCredential,
                $Credentialcreds,
                $SelectSTIG,
                $SelectVuln,
                $ExcludeVuln,
                $ExcludeSTIG,
                $GenerateOQE,
                $NoPrevious,
                $ApplyTattoo,
                $AFPath,
                $ScriptRoot
            )
            $RemoteStartTime = Get-Date

            $Remote_Log = Join-Path -Path $RemoteWorkingDir -ChildPath "Remote_Evaluate-STIG_$($ConnectionResult.NETBIOS).log"

            Write-Log $Remote_Log "==========[Begin Remote Logging]==========" $LogComponent "Info" -OSPlatform $OSPlatform

            Switch ($ConnectionResult.Connected) {
                "5986" {
                    Write-Log $Remote_Log "Connection successful on port 5986. Determined Windows OS." $LogComponent "Info" -OSPlatform $OSPlatform
                }
                "5985" {
                    Write-Log $Remote_Log "Connection successful on port 5985. Determined Windows OS." $LogComponent "Info" -OSPlatform $OSPlatform
                }
                default {
                    Write-Log $Remote_Log "Connection unsuccessful on standard ports (Windows ports 5986/5985)." $LogComponent "Error" -OSPlatform $OSPlatform
                }
            }

            Write-Log $Remote_Log "Scanning : $($ConnectionResult.FQDN)" $LogComponent "Info" -OSPlatform $OSPlatform

            Try {
                Write-Log $Remote_Log "Creating Windows PS Session via HTTPS" $LogComponent "Info" -OSPlatform $OSPlatform

                if ($AltCredential) {
                    $SSLOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
                    $Session = New-PSSession -ComputerName $($ConnectionResult.FQDN) -Credential $Credentialcreds -UseSSL -SessionOption $SSLOptions -ErrorVariable remoteerror -ErrorAction SilentlyContinue
                    if ($remoteerror) {
                        Write-Log $Remote_Log "HTTPS connection failed.  Attempting HTTP connection." $LogComponent "Warning" -OSPlatform $OSPlatform
                        Write-Log $Remote_Log "Creating Windows PS Session via HTTP" $LogComponent "Info" -OSPlatform $OSPlatform

                        $Session = New-PSSession -ComputerName $($ConnectionResult.FQDN) -Credential $Credentialcreds -ErrorVariable remoteerror -ErrorAction SilentlyContinue
                        if ($remoteerror) {
                            Write-Log $Remote_Log "Alternate Credentials failed to create a session.  Falling back to $([Environment]::Username)." $LogComponent "Warning" -OSPlatform $OSPlatform
                            $Session = New-PSSession -ComputerName $($ConnectionResult.FQDN) -ErrorVariable remoteerror -ErrorAction SilentlyContinue
                        }
                    }
                }
                else {
                    $SSLOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
                    $Session = New-PSSession -ComputerName $($ConnectionResult.FQDN) -UseSSL -SessionOption $SSLOptions -ErrorVariable remoteerror -ErrorAction SilentlyContinue
                    if ($remoteerror) {
                        Write-Log $Remote_Log "HTTPS connection failed.  Attempting HTTP connection." $LogComponent "Warning" -OSPlatform $OSPlatform
                        Write-Log $Remote_Log "Creating Windows PS Session via HTTP" $LogComponent "Info" -OSPlatform $OSPlatform
                        $Session = New-PSSession -ComputerName $($ConnectionResult.FQDN) -ErrorVariable remoteerror -ErrorAction SilentlyContinue
                    }
                }

                switch -WildCard ($remoteerror) {
                    "*Access is denied*" {
                        Write-Log $Remote_Log "-ComputerName requires admin rights on $($ConnectionResult.FQDN)" $LogComponent "Error" -OSPlatform $OSPlatform
                    }
                    "*WinRM*" {
                        Write-Log $Remote_Log "-ComputerName requires WinRM on $($ConnectionResult.FQDN)" $LogComponent "Error" -OSPlatform $OSPlatform
                    }
                    "*The user name or password is incorrect.*" {
                        Write-Log $Remote_Log "-ComputerName requires a valid username and password to connect to $($ConnectionResult.FQDN)" $LogComponent "Error" -OSPlatform $OSPlatform
                    }
                    default {
                        Write-Log $Remote_Log "-ComputerName got an error" $LogComponent "Error" -OSPlatform $OSPlatform
                    }
                }

                if (!($Session)) {
                    Write-Log $Remote_Log $remoteerror $LogComponent "Error" -OSPlatform $OSPlatform
                    Write-Log $Remote_Log "==========[End Remote Logging]==========" $LogComponent "Info" -OSPlatform $OSPlatform

                    Add-Content -Path $STIGLog_Remote -Value $(Get-Content $Remote_Log)
                    Remove-Item $Remote_Log
                    $RemoteFailCount["RemoteFail"]++
                    Return
                }

                Write-Log $Remote_Log "Credential: '$(Invoke-Command -ScriptBlock { return whoami } -Session $Session)' used for remote session(s)." $LogComponent "Info" -OSPlatform $OSPlatform

                if ((Invoke-Command -ScriptBlock { (($PsVersionTable.PSVersion).ToString()) -lt 5.1 } -Session $Session)) {
                    Write-Log $Remote_Log "$($ConnectionResult.FQDN) does not meet minimum PowerShell version (5.1)" $LogComponent "Error" -OSPlatform $OSPlatform
                    Write-Log $Remote_Log "==========[End Remote Logging]==========" $LogComponent "Info" -OSPlatform $OSPlatform

                    Add-Content -Path $STIGLog_Remote -Value $(Get-Content $Remote_Log)
                    Remove-Item $Remote_Log
                    $RemoteFailCount["RemoteFail"]++
                    Return
                }

                If (Invoke-Command -ScriptBlock { Test-Path $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer } -Session $Session) {
                    Write-Log $Remote_Log "Removing previous content found in $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer" $LogComponent "Info" -OSPlatform $OSPlatform
                    Invoke-Command -ScriptBlock { Remove-Item $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer -Recurse -Force } -Session $Session
                }
                Invoke-Command -ScriptBlock { $null = New-Item -ItemType Directory -Path $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer } -Session $Session
                Invoke-Command -ScriptBlock { $null = New-Item -ItemType Directory -Path $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer\STIG_Compliance } -Session $Session

                If ($SelectSTIG) {
                    $ESArgs = "-SelectSTIG $($SelectSTIG -join ',') -ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout"
                }
                ElseIf ($ExcludeSTIG) {
                    $ESArgs = "-ExcludeSTIG $($ExcludeSTIG -join ',') -ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout"
                }
                Else {
                    $ESArgs = "-ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout"
                }

                if ($SelectVuln) {
                    $ESArgs = "-SelectVuln $($SelectVuln -join ',') " + $ESArgs
                }

                if ($ExcludeVuln) {
                    $ESArgs = "-ExcludeVuln $($ExcludeVuln -join ',') " + $ESArgs
                }

                If ($Marking) {
                    $ESArgs = "-Marking $Marking " + $ESArgs
                }

                If ($GenerateOQE) {
                    $ESArgs = "-GenerateOQE " + $ESArgs
                }

                If ($NoPrevious) {
                    $ESArgs = "-NoPrevious " + $ESArgs
                }

                If ($ApplyTattoo) {
                    $ESArgs = "-ApplyTattoo " + $ESArgs
                }

                # Clean up orphaned previous scan archives
                If (Test-Path $RemoteWorkingDir\PREVIOUS_$($($ConnectionResult.NETBIOS)).ZIP) {
                    Remove-Item -Path $RemoteWorkingDir\PREVIOUS_$($($ConnectionResult.NETBIOS)).ZIP -Force
                }
                If (Test-Path "$RemoteWorkingDir\$($($ConnectionResult.NETBIOS)).ZIP") {
                    Remove-Item -Path "$RemoteWorkingDir\$($($ConnectionResult.NETBIOS)).ZIP" -Force
                }

                $ProgressPreference = "SilentlyContinue"

                Initialize-FileXferToRemote -NETBIOS $($ConnectionResult.NETBIOS) -RemoteTemp "$env:WINDIR\Temp\Evaluate-STIG_RemoteComputer" -OutputPath $OutputPath -AFPath $AFPath -Remote_Log $Remote_Log -LogComponent $LogComponent -OSPlatform $OSPlatform -RemoteWorkingDir $RemoteWorkingDir -ScriptRoot $ScriptRoot -Session $Session

                Write-Log $Remote_Log "Invoking Evaluate-STIG on $($ConnectionResult.FQDN)" $LogComponent "Info" -OSPlatform $OSPlatform
                Write-Log $Remote_Log "Local logging of scan is stored at $env:WINDIR\Temp\Evaluate-STIG on $($ConnectionResult.FQDN)" $LogComponent "Info" -OSPlatform $OSPlatform

                $RemoteES = Invoke-Command -Session $Session {
                    param(
                        [string]
                        $ESArgs,

                        [string]
                        $OutputPath
                    )

                    if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                        If ((Get-AuthenticodeSignature -FilePath $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer\Evaluate-STIG.ps1).Status -eq "Valid") {
                            $CodeSign = $true
                        }
                        else {
                            $CodeSign = $False
                            Write-Output "Code signing certificate is not installed on $env:COMPUTERNAME"
                        }
                        $ESPath = "$env:WINDIR\Temp\Evaluate-STIG_RemoteComputer\Evaluate-STIG.ps1"
                        $Command = "-Command $($ESPath) $($ESArgs) -OutputPath $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer\STIG_Compliance"
                        $Bypass_Command = " -ExecutionPolicy Bypass -Command $($ESPath) $($ESArgs) -OutputPath $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer\STIG_Compliance"

                        Switch (Get-ExecutionPolicy) {
                            "AllSigned" {
                                If ($CodeSign) {
                                    Start-Process powershell -ArgumentList $Command -Wait
                                }
                                else {
                                    Write-Output "Bypassing '$_' ExecutionPolicy on $env:COMPUTERNAME"
                                    Start-Process powershell -ArgumentList $Bypass_Command -Wait
                                }
                            }
                            "Default" {
                                Write-Output "Bypassing '$_' ExecutionPolicy on $env:COMPUTERNAME"
                                Start-Process powershell -ArgumentList $Bypass_Command -Wait
                            }
                            "RemoteSigned" {
                                If ($CodeSign) {
                                    Start-Process powershell -ArgumentList $Command -Wait
                                }
                                else {
                                    Write-Output "Bypassing '$_' ExecutionPolicy on $env:COMPUTERNAME"
                                    Start-Process powershell -ArgumentList $Bypass_Command -Wait
                                }
                            }
                            "Restricted" {
                                Write-Output "Bypassing '$_' ExecutionPolicy on $env:COMPUTERNAME"
                                Start-Process powershell -ArgumentList $Bypass_Command -Wait
                            }
                            "Undefined" {
                                Write-Output "Bypassing '$_' ExecutionPolicy on $env:COMPUTERNAME"
                                Start-Process powershell -ArgumentList $Bypass_Command -Wait
                            }
                            default {
                                Start-Process powershell -ArgumentList $Command -Wait
                            }
                        }

                        Write-Output " - Remote scan completed."
                    }
                    else {
                        Write-Output "ERROR: You must run this from an elevated PowerShell session on the Remote computer."
                        Write-Output "==========[End Remote Logging]=========="
                        Return
                    }
                } -ArgumentList ($ESArgs, $OutputPath) -ErrorAction SilentlyContinue -InformationAction Ignore

                $RemoteES | ForEach-Object { Write-Log $Remote_Log $_ $LogComponent "Info" -OSPlatform $OSPlatform }

                if ($SelectVuln) {
                    $NetBIOS = "_Partial_$($ConnectionResult.NETBIOS)"
                }
                else {
                    $NetBIOS = $($ConnectionResult.NETBIOS)
                }

                If (Invoke-Command -ScriptBlock { Return Test-Path "$($env:WINDIR)\Temp\Evaluate-STIG_RemoteComputer\STIG_Compliance\$($NetBIOS)" } -Session $Session) {
                    Initialize-FileXferFromRemote -NETBIOS $NetBIOS -RemoteTemp "$env:WINDIR\Temp\Evaluate-STIG_RemoteComputer" -OutputPath $OutputPath -Remote_Log $Remote_Log -LogComponent $LogComponent -OSPlatform $OSPlatform -RemoteWorkingDir $RemoteWorkingDir -ScriptRoot $ScriptRoot -Session $Session
                }
                Else {
                    Write-Log $Remote_Log "No Evaluate-STIG results were found on $($ConnectionResult.FQDN)." $LogComponent "Info" -OSPlatform $OSPlatform
                    $OfflineList.Add($ConnectionResult.FQDN)
                }

                If (Invoke-Command -ScriptBlock { Test-Path $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer } -Session $Session) {
                    Invoke-Command -ScriptBlock { Remove-Item $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer -Recurse -Force } -Session $Session
                }

                $Session | Remove-PSSession

                $TotalCKLs = (Get-ChildItem -Path "$OutputPath\$NetBIOS\Checklist" | Where-Object Extension -EQ '.ckl' | Measure-Object).Count

                $TimeToComplete = New-TimeSpan -Start $RemoteStartTime -End (Get-Date)
                $FormatedTime = "{0:c}" -f $TimeToComplete
                Write-Log $Remote_Log "Total CKLs - $($TotalCKLs)" $LogComponent "Info" -OSPlatform $OSPlatform
                Write-Log $Remote_Log "Total Time - $($FormatedTime)" $LogComponent "Info" -OSPlatform $OSPlatform
                Write-Log $Remote_Log "==========[End Remote Logging]==========" $LogComponent "Info" -OSPlatform $OSPlatform

                Add-Content -Path $STIGLog_Remote -Value $(Get-Content $Remote_Log)
                Remove-Item $Remote_Log

                $ProgressPreference = "Continue"
            }
            Catch {
                Write-Log $Remote_Log "ERROR: $($_.Exception.Message)" $LogComponent "Error" -OSPlatform $OSPlatform
                Write-Log $Remote_Log "Total Time - $($FormatedTime)" $LogComponent "Info" -OSPlatform $OSPlatform
                Write-Log $Remote_Log "==========[End Remote Logging]==========" $LogComponent "Info" -OSPlatform $OSPlatform

                Add-Content -Path $STIGLog_Remote -Value $(Get-Content $Remote_Log)
                Remove-Item $Remote_Log

                If ($Session) {
                    $Session | Remove-PSSession
                }
                $ProgressPreference = "Continue"
            }
        }

        $RemoteFailCount = [hashtable]::Synchronized(@{})

        $Params = @{
            STIGLog_Remote   = $STIGLog_Remote
            LogComponent     = $LogComponent
            OSPlatform       = $OSPlatform
            RemoteWorkingDir = $RemoteWorkingDir
            ScanType         = $ScanType
            VulnTimeout      = $VulnTimeout
            AnswerKey        = $AnswerKey
            OutputPath       = $OutputPath
            ScriptRoot       = $ES_Path
        }

        if ($AltCredential) {
            $Params.AltCredential = $True
            $Params.CredentialCreds = $Credentialcreds
        }
        else {
            $Params.AltCredential = $False
        }

        if ($SelectSTIG) {
            $Params.SelectSTIG = $SelectSTIG
        }
        else {
            $Params.SelectSTIG = $False
        }

        if ($SelectVuln) {
            $Params.SelectVuln = $SelectVuln
        }
        else {
            $Params.SelectVuln = $False
        }

        if ($ExcludeVuln) {
            $Params.ExcludeVuln = $ExcludeVuln
        }
        else {
            $Params.ExcludeVuln = $False
        }

        if ($ExcludeSTIG) {
            $Params.ExcludeSTIG = $ExcludeSTIG
        }
        else {
            $Params.ExcludeSTIG = $False
        }

        if ($Marking) {
            $Params.Marking = $Marking
        }
        else {
            $Params.Marking = $False
        }

        if ($GenerateOQE) {
            $Params.GenerateOQE = $GenerateOQE
        }
        else {
            $Params.GenerateOQE = $False
        }

        if ($NoPrevious) {
            $Params.NoPrevious = $NoPrevious
        }
        else {
            $Params.NoPrevious = $False
        }

        if ($ApplyTattoo) {
            $Params.ApplyTattoo = $ApplyTattoo
        }
        else {
            $Params.ApplyTattoo = $False
        }

        if ($AFPath) {
            $Params.AFPath = $AFPath
        }
        else {
            $Params.AFPath = $False
        }

        if ($ThrottleLimit) {
            $MaxThreads = $ThrottleLimit
        }
        else {
            $MaxThreads = 10
        }

        # https://learn-powershell.net/2013/04/19/sharing-variables-and-live-objects-between-powershell-runspaces/

        $runspaces = New-Object System.Collections.ArrayList
        $sessionstate = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()
        $sessionstate.variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList 'RemoteFailCount', $RemoteFailCount, ''))

        Get-ChildItem function:/ | ForEach-Object {
            $definition = Get-Content "Function:\$($_.Name)"
            $SessionStateFunction = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $_.Name, $definition
            $sessionstate.Commands.Add($SessionStateFunction)
        }

        $runspacepool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $sessionstate, $Host)
        $runspacepool.ApartmentState = "STA"
        $runspacepool.Open()

        Foreach ($ConnectionResult in $($ConnectionResults | Where-Object { ($_.Connected -ne "22") -and ($_.FQDN -notin $OfflineList) })) {
            $Job = [powershell]::Create().AddScript($RemoteScriptBlock).AddArgument($ConnectionResult).AddParameters($Params)
            $Job.Streams.ClearStreams()
            $Job.RunspacePool = $RunspacePool

            # Create a temporary collection for each runspace
            $temp = "" | Select-Object Job, Runspace, FQDN
            $Temp.FQDN = $ConnectionResult.FQDN
            $temp.Job = $Job

            # Save the handle output when calling BeginInvoke() that will be used later to end the runspace
            $temp.Runspace = $Job.BeginInvoke()
            $null = $runspaces.Add($temp)
        }

        if (($runspaces | Measure-Object).count -gt 0) {
            Get-RunspaceData -Runspaces $Runspaces -Wait -Usage Remote
        }

        $RunspacePool.Close()
        $RunspacePool.Dispose()

        $RemoteLinuxFail = 0

        if (($LinuxList | Measure-Object).count -gt 0) {
            $SSHUsername = Read-Host "Enter username to SSH to $(($LinuxList | Measure-Object).count) Linux host(s)"

            Foreach ($LinuxHost in $LinuxList) {
                $Remote_Log = Join-Path -Path $RemoteWorkingDir -ChildPath "Remote_Evaluate-STIG_$($LinuxHost.NETBIOS).log"
                Write-Host ""

                If ($PowerShellVersion -ge [Version]"7.1") {
                    Try {
                        $RemoteStartTime = Get-Date

                        Write-Log $Remote_Log "Connection successful on port 22. Determined Linux OS." $LogComponent "Info" -OSPlatform $OSPlatform
                        Write-Log $Remote_Log "Scanning : $($LinuxHost.FQDN)" $LogComponent "Info" -OSPlatform $OSPlatform

                        Try {
                            $Session = New-PSSession -HostName $LinuxHost.FQDN -UserName $SSHUsername -SSHTransport -ErrorAction Stop
                            $SessionUserName = $SSHUsername
                        }
                        Catch {
                            Write-Log $Remote_Log "SSH Session failed for $($LinuxHost.FQDN).  Requesting different SSH username" $LogComponent "Warning" -OSPlatform $OSPlatform
                            Write-Host "SSH Session failed for $($LinuxHost.FQDN).  Requesting different SSH username"
                            $AltSSHUsername = Read-Host "Enter username to SSH to $($LinuxHost.FQDN)"
                            $SessionUserName = $AltSSHUsername
                            Try {
                                $Session = New-PSSession -HostName $LinuxHost.FQDN -UserName $AltSSHUsername -SSHTransport -ErrorAction Stop
                            }
                            Catch {
                                Write-Log $Remote_Log "SSH Session failed for $($LinuxHost.FQDN)." $LogComponent "Warning" -OSPlatform $OSPlatform
                                Write-Host "SSH Session failed for $($LinuxHost.FQDN)."
                            }
                        }

                        If (Invoke-Command -ScriptBlock { Test-Path /tmp/Evaluate-STIG_RemoteComputer } -Session $Session) {
                            Write-Log $Remote_Log "Removing previous content found in /tmp/Evaluate-STIG_RemoteComputer" $LogComponent "Info" -OSPlatform $OSPlatform
                            Invoke-Command -ScriptBlock { Remove-Item /tmp/Evaluate-STIG_RemoteComputer -Recurse -Force } -Session $Session
                        }
                        Invoke-Command -ScriptBlock { $null = New-Item -ItemType Directory -Path /tmp/Evaluate-STIG_RemoteComputer } -Session $Session
                        Invoke-Command -ScriptBlock { $null = New-Item -ItemType Directory -Path /tmp/Evaluate-STIG_RemoteComputer/STIG_Compliance } -Session $Session

                        $DefaultOutputPath = "/tmp/Evaluate-STIG_RemoteComputer/STIG_Compliance"

                        if ($SelectSTIG) {
                            $ESArgs = "-SelectSTIG $($SelectSTIG -join ',') -ScanType $ScanType -AnswerKey $AnswerKey -OutputPath $DefaultOutputPath"
                        }
                        elseif ($ExcludeSTIG) {
                            $ESArgs = "-ExcludeSTIG $($ExcludeSTIG -join ',') -ScanType $ScanType -AnswerKey $AnswerKey -OutputPath $DefaultOutputPath"
                        }
                        else {
                            $ESArgs = "-ScanType $ScanType -AnswerKey $AnswerKey -OutputPath $DefaultOutputPath"
                        }

                        if ($SelectVuln) {
                            $ESArgs = "-SelectVuln $($SelectVuln -join ',') " + $ESArgs
                        }

                        if ($ExcludeVuln) {
                            $ESArgs = "-ExcludeVuln $($ExcludeVuln -join ',') " + $ESArgs
                        }

                        if ($Marking) {
                            $ESArgs = "-Marking $Marking " + $ESArgs
                        }

                        if ($GenerateOQE) {
                            $ESArgs = "-GenerateOQE " + $ESArgs
                        }

                        If ($NoPrevious) {
                            $ESArgs = "-NoPrevious " + $ESArgs
                        }

                        If ($ApplyTattoo) {
                            $ESArgs = "-ApplyTattoo " + $ESArgs
                        }

                        # Clean up orphaned previous scan archives
                        If (Test-Path "$RemoteWorkingDir\PREVIOUS_$($LinuxHost.NETBIOS).ZIP") {
                            Remove-Item -Path "$RemoteWorkingDir\PREVIOUS_$($LinuxHost.NETBIOS).ZIP" -Force
                        }
                        If (Test-Path "$RemoteWorkingDir\$($LinuxHost.NETBIOS).ZIP") {
                            Remove-Item -Path "$RemoteWorkingDir\$($LinuxHost.NETBIOS).ZIP" -Force
                        }

                        $ProgressPreference = "SilentlyContinue"

                        Initialize-FileXferToRemote -NETBIOS $($LinuxHost.NETBIOS) -RemoteTemp "/tmp/Evaluate-STIG_RemoteComputer" -OutputPath $OutputPath -AFPath $AFPath -Remote_Log $Remote_Log -LogComponent $LogComponent -OSPlatform $OSPlatform -RemoteWorkingDir $RemoteWorkingDir -ScriptRoot $ES_Path -Session $Session

                        Write-Host " - Invoking Evaluate-STIG on $($LinuxHost.FQDN). This may take several minutes."
                        Write-Log $Remote_Log "Invoking Evaluate-STIG on $($LinuxHost.FQDN)." $LogComponent "Info" -OSPlatform $OSPlatform

                        Write-Host "    Local logging of scan is stored at /tmp/Evaluate-STIG on $($LinuxHost.FQDN)"
                        Write-Log $Remote_Log "Local logging of scan is stored at /tmp/Evaluate-STIG on $($LinuxHost.FQDN)" $LogComponent "Info" -OSPlatform $OSPlatform

                        #Test for NOPASSWD
                        $NoPasswdTest = Invoke-Command -ScriptBlock { if ((sudo whoami) -ne "root") {
                                Return 2
                            } } -Session $Session -ErrorAction SilentlyContinue -InformationAction Ignore

                        if ($NoPasswdTest -eq 2) {
                            do {
                                $sudoPass = Read-Host "[sudo] password for $SessionUserName" -AsSecureString
                                $creds = New-Object System.Management.Automation.PSCredential($SessionUserName, $sudoPass)
                                $sudoPass = $creds.GetNetworkCredential().Password

                                $SudoCheck = Invoke-Command -ScriptBlock {
                                    param(
                                        [String]
                                        $SudoPass
                                    )
                                    if (($sudoPass | sudo -S whoami) -ne "root") {
                                        Write-Host "ERROR: sudo: incorrect password attempt" -ForegroundColor Red -BackgroundColor Black
                                        Return 2
                                    }
                                    else { return 0 }
                                } -Session $Session -ArgumentList $sudoPass -ErrorAction SilentlyContinue -InformationAction Ignore
                            }while ($SudoCheck -ne 0)
                        }
                        else {
                            $null = $sudoPass
                        }

                        $RemoteES = Invoke-Command -Session $session {
                            param(
                                [String]
                                $SudoPass,

                                [String]
                                $ESArgs,

                                [string]
                                $DefaultOutputPath,

                                [string]
                                $SSHUsername,

                                [string]
                                $OutputPath
                            )

                            if ($null -ne $SudoPass) {
                                if (($sudoPass | sudo -S whoami) -ne "root") {
                                    Write-Host "ERROR: sudo: incorrect password attempt" -ForegroundColor Red -BackgroundColor Black
                                    Return 2
                                }

                                if (!(Test-Path $DefaultOutputPath)) {
                                    $SudoPass | sudo -S mkdir $DefaultOutputPath
                                }
                            }
                            else {
                                if (!(Test-Path $DefaultOutputPath)) {
                                    sudo mkdir $DefaultOutputPath
                                }
                            }

                            # Now you have cached your sudo password you should be able to call it normally (up to whatever timeout you have configured)
                            $SudoPass | sudo -S pwsh -command "Start-Process pwsh -ArgumentList '-command /tmp/Evaluate-STIG_RemoteComputer/Evaluate-STIG.ps1 $ESArgs' -Wait; chown -R $SSHUsername`: /tmp/Evaluate-STIG_RemoteComputer"
                            Write-Host " - Remote scan completed."
                        } -ArgumentList ($sudoPass, $ESArgs, $DefaultOutputPath, $SessionUserName, $OutputPath) -ErrorAction SilentlyContinue -InformationAction Ignore

                        if ($SelectVuln) {
                            $NetBIOS = "_Partial_$($LinuxHost.NETBIOS)"
                        }
                        else {
                            $NetBIOS = $($LinuxHost.NETBIOS)
                        }

                        if (Invoke-Command -ScriptBlock { param ($DefaultOutputPath, $NetBIOS)
                                $Path = "$DefaultOutputPath/$NetBIOS"
                                Return (pwsh -command "Test-Path $Path" )
                            } -Session $Session -ArgumentList ($DefaultOutputPath, $NetBIOS)) {
                            Initialize-FileXferFromRemote -NETBIOS $NetBIOS -RemoteTemp "/tmp/Evaluate-STIG_RemoteComputer" -OutputPath $OutputPath -Remote_Log $Remote_Log -LogComponent $LogComponent -OSPlatform $OSPlatform -RemoteWorkingDir $RemoteWorkingDir -ScriptRoot $ScriptRoot -Session $Session
                        }
                        elseif ($RemoteES -eq 2) {
                            $RemoteLinuxFail++
                        }
                        else {
                            Write-Log $Remote_Log "No Evaluate-STIG results were found on $($LinuxHost.FQDN)." $LogComponent "Info" -OSPlatform $OSPlatform
                            $OfflineList.Add($LinuxHost.NETBIOS)
                            $RemoteLinuxFail++
                        }

                        If (Invoke-Command -ScriptBlock { Test-Path /tmp/Evaluate-STIG_RemoteComputer } -Session $Session) {
                            Invoke-Command -ScriptBlock { Remove-Item /tmp/Evaluate-STIG_RemoteComputer -Recurse -Force } -Session $Session
                        }

                        $Session | Remove-PSSession

                        $TotalCKLs = (Get-ChildItem -Path "$OutputPath\$NetBIOS\Checklist" | Where-Object Extension -EQ '.ckl' | Measure-Object).Count

                        $TimeToComplete = New-TimeSpan -Start $RemoteStartTime -End (Get-Date)
                        $FormatedTime = "{0:c}" -f $TimeToComplete
                        Write-Host "Total CKLs - $($TotalCKLs)"
                        Write-Host "Total Time - $($FormatedTime)"
                        Write-Log $Remote_Log "Total CKLs - $($TotalCKLs)" $LogComponent "Info" -OSPlatform $OSPlatform
                        Write-Log $Remote_Log "Total Time - $($FormatedTime)" $LogComponent "Info" -OSPlatform $OSPlatform
                        Write-Log $Remote_Log "==========[End Remote Logging]==========" $LogComponent "Info" -OSPlatform $OSPlatform

                        Add-Content -Path $STIGLog_Remote -Value $(Get-Content $Remote_Log)
                        Remove-Item $Remote_Log

                        $ProgressPreference = "Continue"
                    }
                    Catch {
                        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Black
                        Write-Log $Remote_Log "ERROR: $($_.Exception.Message)" $LogComponent "Error" -OSPlatform $OSPlatform
                        Write-Log $Remote_Log "==========[End Remote Logging]==========" $LogComponent "Info" -OSPlatform $OSPlatform

                        Add-Content -Path $STIGLog_Remote -Value $(Get-Content $Remote_Log)
                        Remove-Item $Remote_Log

                        If ($Session) {
                            $Session | Remove-PSSession
                        }
                        $ProgressPreference = "Continue"
                    }
                }
                Else {
                    Write-Host "$($LinuxHost.FQDN) is running a Linux Operating System. PowerShell $($PowerShellVersion -join '.') detected.  Evaluate-STIG requires PowerShell 7.1."
                    $RemoteLinuxFail++
                    Write-Log $Remote_Log "$($LinuxHost.FQDN) is running a Linux Operating System. PowerShell $($PowerShellVersion -join '.') detected.  Evaluate-STIG requires PowerShell 7.1." $LogComponent "Error" -OSPlatform $OSPlatform
                    Write-Log $Remote_Log "==========[End Remote Logging]==========" $LogComponent "Info" -OSPlatform $OSPlatform

                    Add-Content -Path $STIGLog_Remote -Value $(Get-Content $Remote_Log)
                    Remove-Item $Remote_Log
                }
            }
        }

        $RemoteTimeToComplete = New-TimeSpan -Start $StartTime -End (Get-Date)
        $FormatedTime = "{0:c}" -f $RemoteTimeToComplete
        Write-Log $STIGLog_Remote "We're done!" $LogComponent "Info" -OSPlatform $OSPlatform
        Write-Log $STIGLog_Remote "Total Time - $($FormatedTime)" $LogComponent "Info" -OSPlatform $OSPlatform
        Write-Log $STIGLog_Remote "Total Hosts - $(($ComputerList | Measure-Object).count)" $LogComponent "Info" -OSPlatform $OSPlatform
        Write-Log $STIGLog_Remote "Total Hosts with Error - $($RemoteLinuxFail + $(if ($RemoteFailCount.Values -ge 1){$($RemoteFailCount.Values)}else{"0"}))" $LogComponent "Info" -OSPlatform $OSPlatform
        Write-Log $STIGLog_Remote "Total Hosts Not Resolved - $RemoteUnresolveCount" $LogComponent "Info" -OSPlatform $OSPlatform
        Write-Log $STIGLog_Remote "Total Hosts Offline - $(($OfflineList | Measure-Object).Count)" $LogComponent "Info" -OSPlatform $OSPlatform
        Write-Host ""
        Write-Host ""
        Write-Host "Done!" -ForegroundColor Green
        Write-Host "Total Time - $($FormatedTime)" -ForegroundColor Green
        Write-Host "Total Hosts - $(($ComputerList | Measure-Object).count)" -ForegroundColor Green
        if ($($RemoteLinuxFail + $(if ($RemoteFailCount.Values -ge 1) {
                        $($RemoteFailCount.Values)
                    }
                    else {
                        "0"
                    })) -gt 0) {
            Write-Host "Total Hosts with Error - $($RemoteLinuxFail + $(if ($RemoteFailCount.Values -ge 1){$($RemoteFailCount.Values)}else{"0"}))" -ForegroundColor Red
        }
        Write-Host "Total Hosts Not Resolved - $RemoteUnresolveCount" -ForegroundColor Yellow
        Write-Host "Total Hosts Offline - $(($OfflineList | Measure-Object).Count)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Results saved to " -ForegroundColor Green -NoNewline; Write-Host "$($OutputPath)" -ForegroundColor Cyan
        Write-Host "Local logging of remote scan(s) stored at " -ForegroundColor Green -NoNewline; Write-Host "$($RemoteScanDir)" -ForegroundColor DarkCyan
        Write-Host "Offline Results saved to " -ForegroundColor Green -NoNewline; Write-Host "$RemoteScanDir\Offline_Hosts.txt" -ForegroundColor Cyan
        Write-Host ""

        If ($SelectVuln) {
            $RemotePathArray = @()
            $WindowsList | Foreach-Object {$RemotePathArray += $(Join-Path $OutputPath -ChildPath "_Partial_$($_.NETBIOS)")}
            $Linuxlist | Foreach-Object {$RemotePathArray += $(Join-Path $OutputPath -ChildPath "_Partial_$($_.NETBIOS)")}
            $SelectedRemoteVulns = New-Object System.Collections.Generic.List[System.Object]
            $SelectVuln_CKLs = Get-ChildItem -Path (Join-Path $RemotePathArray -ChildPath "Checklist")| Where-Object { ($_.Extension -eq ".ckl") }

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
                        $SelectedRemoteVulns.Add($NewObj) | Out-Null
                    }
                }
            }
        }

        if (($OfflineList | Measure-Object).Count -gt 0) {
            if (Test-Path "$RemoteScanDir\Offline_Hosts.txt") {
                Clear-Content "$RemoteScanDir\Offline_Hosts.txt"
            }
            $OfflineList | Sort-Object -Unique | ForEach-Object {
                Add-Content -Path "$RemoteScanDir\Offline_Hosts.txt" -Value $_
            }
        }

        If (Test-Path $RemoteWorkingDir\ESCONTENT.ZIP) {
            Remove-Item -Path $RemoteWorkingDir\ESCONTENT.ZIP -Force
        }
        If (Test-Path $RemoteWorkingDir\AFILES.ZIP) {
            Remove-Item -Path $RemoteWorkingDir\AFILES.ZIP -Force
        }

        Return $SelectedRemoteVulns
    }
    Catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Black
        Write-Log $STIGLog_Remote "ERROR: $($_.Exception.Message)" $LogComponent "Error" -OSPlatform $OSPlatform
    }
}

Function Get-FileUpdatesFromRepo {
    Param (
        [Parameter(Mandatory = $true)]
        [String] $PS_Path,

        [Parameter(Mandatory = $false)]
        [String] $Proxy
    )

    Try {
        $UpdateRequired = $false

        Write-Host "Checking for updates to Evaluate-STIG..." -ForegroundColor Gray
        If ($Proxy) {
            Write-Host "Using proxy '$Proxy'" -ForegroundColor Gray
        }
        $URLs = @(
            "https://spork.navsea.navy.mil/nswc-crane-division/evaluate-stig/-/archive/master/evaluate-stig-master.zip?path=Src/Evaluate-STIG",
            "https://spork.navsea.navy.mil/nswc-crane-division/evaluate-stig/-/archive/master/evaluate-stig-master.zip?path=PowerShell/Src/Evaluate-STIG",
            "https://spork.navsea.navy.mil/nswc-crane-division/evaluate-stig/-/archive/master/evaluate-stig-master.zip?path=Windows/Src/Evaluate-STIG"
        )

        $LocalContent = Get-ChildItem $PS_Path -Recurse | Where-Object { ($_.Name -ne "AnswerFiles") -and ($_.DirectoryName -notlike $(Join-Path -Path $PS_Path -ChildPath "AnswerFiles*") -and ($_.Name -ne "_Update.tmp") -and ($_.DirectoryName -notlike $(Join-Path -Path $PS_Path -ChildPath "_Update.tmp*"))) }
        $LocalVersion = (Select-String -Path $(Join-Path -Path $PS_Path -ChildPath "Evaluate-STIG.ps1") -Pattern '\$EvaluateStigVersion = ' | ForEach-Object { $_.Line.split(":") }).replace('$EvaluateStigVersion = ', '').Replace('"', '').Trim()

        # Create temp folder
        $Update_tmp = (Join-Path -Path $PS_Path -ChildPath "_Update.tmp")
        If (Test-Path $Update_tmp) {
            Remove-Item $Update_tmp -Recurse -Force
        }
        $null = New-Item -Path $PS_Path -Name "_Update.tmp" -ItemType Directory

        # Download upstream content
        $ZipFile = $(Join-Path -Path $PS_Path -ChildPath "evaluate-stig-master.zip")
        If ($Islinux) {
            $pkg_mgr = (Get-Content /etc/os-release | grep "ID_LIKE=").replace("ID_LIKE=", "").replace('"', "")
            Switch ($pkg_mgr) {
                "debian" {
                    If (apt -qq list curl 2>/dev/null | grep installed) {
                        $curl_installed = $true
                    }
                }
                "fedora" {
                    If (rpm -qa | grep curl) {
                        $curl_installed = $true
                    }
                }
            }
            If ($curl_installed) {
                ForEach ($URL in $URLs) {
                    If ($Proxy) {
                        curl -k $URL --proxy $Proxy --output evaluate-stig-master.zip
                    }
                    Else {
                        curl -k $URL --output evaluate-stig-master.zip
                    }
                    If ((Get-Item $ZipFile).Length -gt 0) {
                        Break
                    }
                }
            }
            Else {
                Throw "Curl is required to be installed to download updates."
            }
        }
        Else {
            $WebClient = New-Object System.Net.WebClient
            If ($Proxy) {
                $WebProxy = New-Object System.Net.WebProxy($Proxy, $true)
                $WebClient.Proxy = $WebProxy
            }
            ForEach ($URL in $URLs) {
                $WebClient.DownloadFile($URL, $ZipFile)
                If ((Get-Item $ZipFile).Length -gt 0) {
                    Break
                }
            }
        }

        # change extension filter to a file extension that exists
        # inside your ZIP file
        $Filter = '/Evaluate-STIG/'

        # load ZIP methods
        Add-Type -AssemblyName System.IO.Compression.FileSystem

        # open ZIP archive for reading
        $Zip = [IO.Compression.ZipFile]::OpenRead($ZipFile)

        # Exclude /AnswerFiles/ so we don't overwrite user customizations
        $Exclude = "/AnswerFiles/"

        # find all files in ZIP that match the filter (i.e. file extension)
        $Zip.Entries |
        Where-Object { ($_.FullName -match $Filter) -and ($_.FullName -notmatch $Exclude) } | ForEach-Object {
            # extract the selected items from the ZIP archive
            # and copy them to the out folder
            $FileName = $_.Name
            If ($Filename) {
                $Path_strip = ($_.FullName).replace("evaluate-stig-master-Src-Evaluate-STIG/Src/Evaluate-STIG", "").Replace($FileName, "")
                $FilePath = "$(Join-Path -Path $Update_tmp -ChildPath $Path_strip)"
                [IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$FilePath$FileName", $true)
            }
            Else {
                $Path_strip = ($_.FullName).replace("evaluate-stig-master-Src-Evaluate-STIG/Src/Evaluate-STIG", "")
                $null = New-Item -Path $(Join-Path -Path $Update_tmp -ChildPath $Path_strip) -ItemType Directory -Force
            }
        }
        # close ZIP file
        $Zip.Dispose()
        Remove-Item -Path $ZipFile -Force

        $UpstreamVersion = (Select-String -Path $(Join-Path -Path $Update_tmp -ChildPath "Evaluate-STIG.ps1") -Pattern '\$EvaluateStigVersion = ' | ForEach-Object { $_.Line.split(":") }).replace('$EvaluateStigVersion = ', '').Replace('"', '').Trim()

        # Build list objects
        $LocalContentList = New-Object System.Collections.Generic.List[System.Object]
        [XML]$FileList = Get-Content ($LocalContent | Where-Object { $_.Name -eq "FileList.XML" }).FullName
        ForEach ($Item in $LocalContent) {
            If ($Item.PSIsContainer -eq $true) {
                $Hash = ""
            }
            Else {
                $FileListAttributes = (Select-Xml -Xml $FileList -XPath "//File[@Name=""$($Item.Name)""]").Node
                If ($FileListAttributes.Path -match "Modules") {
                    $IsModule = $True
                }
                else {
                    $IsModule = $False
                }
                $ScanReq = $FileListAttributes.ScanReq
                $Hash = (Get-FileHash $Item.FullName -Algorithm SHA256).Hash

            }
            $NewObj = [PSCustomObject]@{
                PSIsContainer = $Item.PSIsContainer
                Name          = $Item.Name
                FullName      = $Item.FullName
                IsModule      = $IsModule
                ScanRequired  = $ScanReq
                Hash          = $Hash
            }
            $LocalContentList.Add($NewObj)
        }

        $UpstreamContent = Get-ChildItem $Update_tmp -Recurse
        $UpstreamContentList = New-Object System.Collections.Generic.List[System.Object]
        [XML]$FileList = Get-Content ($UpstreamContent | Where-Object { $_.Name -eq "FileList.XML" }).FullName
        ForEach ($Item in $UpstreamContent) {
            If ($Item.PSIsContainer -eq $true) {
                $Hash = ""
            }
            Else {
                $FileListAttributes = (Select-Xml -Xml $FileList -XPath "//File[@Name=""$($Item.Name)""]").Node
                If ($FileListAttributes.Path -match "Modules") {
                    $IsModule = $True
                }
                else {
                    $IsModule = $False
                }
                $ScanReq = $FileListAttributes.ScanReq
                $Hash = (Get-FileHash $Item.FullName -Algorithm SHA256).Hash
            }
            $NewObj = [PSCustomObject]@{
                PSIsContainer = $Item.PSIsContainer
                Name          = $Item.Name
                FullName      = $Item.FullName
                IsModule      = $IsModule
                ScanRequired  = $ScanReq
                Hash          = $Hash
            }
            $UpstreamContentList.Add($NewObj)
        }

        # Compare local file hashes to upstream hashes
        ForEach ($Item in ($UpstreamContentList | Where-Object PSIsContainer -NE $true)) {
            $LocalFile = $Item.FullName.Replace($Update_tmp, $PS_Path)
            If (-Not((Test-Path $LocalFile) -and (($LocalContentList | Where-Object FullName -EQ $LocalFile).Hash -eq $Item.Hash))) {
                $UpdateRequired = $true
                Break
            }
        }

        # Look for items that are not part of upstream content (excludes Answer Files)
        ForEach ($Item in $LocalContentList) {
            If ((Test-Path $Item.FullName) -and ($Item.FullName -notin $UpstreamContentList.FullName.Replace($Update_tmp, $PS_Path))) {
                $UpdateRequired = $true
                Break
            }
        }

        # If an update is required, wipe all local content and sync with upstream (excludes Answer Files)
        If ($UpdateRequired -eq $true) {
            $OptionalList = New-Object System.Collections.Generic.List[System.Object]
            ForEach ($Item in $LocalContentList) {
                If ($Item.ScanRequired -eq "Optional") {
                    $OptionalModule = $True
                    $OptionalList.Add($Item.Name)
                }
                If (Test-Path $Item.FullName) {
                    Remove-Item $Item.FullName -Recurse -Force
                }
            }
            Copy-Item $(Join-Path -Path $Update_tmp -ChildPath "*") -Destination $PS_Path -Recurse
        }

        # If Answer Files folder doesn't exist for some reason, create it since it's the default for -AFPath
        If (-Not(Test-Path $(Join-Path -Path $PS_Path -ChildPath "AnswerFiles"))) {
            New-Item -Path $PS_Path -Name "AnswerFiles" -ItemType Directory | Out-Null
        }

        # Clean up temp files
        If (Test-Path $Update_tmp) {
            Remove-Item -Path $Update_tmp -Recurse -Force
        }
        If (Test-Path $ZipFile) {
            Remove-Item $ZipFile -Force
        }

        If ($UpdateRequired -eq $true) {
            If ($OptionalModule) {
                Write-Host "Successfully updated to Evaluate-STIG $($UpstreamVersion)." -ForegroundColor Green
                Write-Host "The following Optional files require redownloading:" -ForegroundColor Yellow
                $OptionalList | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
                Return
            }
            Else {
                Return "Successfully updated to Evaluate-STIG $($UpstreamVersion)."
            }
        }
        Else {
            Return "Local Evaluate-STIG $($LocalVersion) requires no updating."
        }
    }
    Catch {
        $Msg = $_.Exception.Message
        # Clean up temp files
        If (Test-Path $Update_tmp) {
            Remove-Item -Path $Update_tmp -Recurse -Force
        }
        If (Test-Path $ZipFile) {
            Remove-Item $ZipFile -Force
        }

        Return $Msg
    }
}

Function Get-Creds {
    <#
.NOTES
Author: Joshua Chase
Last Modified: 09 September 2019
Version: 1.1.0
C# signatures obtained from PInvoke.
#>
    [cmdletbinding()]
    Param()
    $Code = @"
using System;
using System.Text;
using System.Security;
using System.Management.Automation;
using System.Runtime.InteropServices;
public class Credentials
{
    private const int CREDUIWIN_GENERIC = 1;
    private const int CREDUIWIN_CHECKBOX = 2;
    private const int CREDUIWIN_AUTHPACKAGE_ONLY = 16;
    private const int CREDUIWIN_IN_CRED_ONLY = 32;
    private const int CREDUIWIN_ENUMERATE_ADMINS = 256;
    private const int CREDUIWIN_ENUMERATE_CURRENT_USER = 512;
    private const int CREDUIWIN_SECURE_PROMPT = 4096;
    private const int CREDUIWIN_PACK_32_WOW = 268435456;
    [DllImport("credui.dll", CharSet = CharSet.Unicode)]
    private static extern uint CredUIPromptForWindowsCredentials(ref CREDUI_INFO notUsedHere,
        int authError,
        ref uint authPackage,
        IntPtr InAuthBuffer,
        uint InAuthBufferSize,
        out IntPtr refOutAuthBuffer,
        out uint refOutAuthBufferSize,
        ref bool fSave,
        int flags);
    [DllImport("credui.dll", CharSet = CharSet.Unicode)]
    private static extern bool CredUnPackAuthenticationBuffer(int dwFlags,
        IntPtr pAuthBuffer,
        uint cbAuthBuffer,
        StringBuilder pszUserName,
        ref int pcchMaxUserName,
        StringBuilder pszDomainName,
        ref int pcchMaxDomainame,
        StringBuilder pszKey,
        ref int pcchMaxKey);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDUI_INFO
    {
        public int cbSize;
        public IntPtr hwndParent;
        public string pszMessageText;
        public string pszCaptionText;
        public IntPtr hbmBanner;
    }
    public static PSCredential getPSCred()
    {
        bool save = false;
        int authError = 0;
        uint result;
        uint authPackage = 0;
        IntPtr outCredBuffer;
        uint outCredSize;
        PSCredential psCreds = null;
        var credui = new CREDUI_INFO
                                {
                                    pszCaptionText = "Enter your credentials",
                                    pszMessageText = "These credentials will be used for Evaluate-STIG remote scans"
                                };
        credui.cbSize = Marshal.SizeOf(credui);
        while (true) //Show the dialog again and again, until Cancel is clicked or the entered credentials are correct.
        {
            //Show the dialog
            result = CredUIPromptForWindowsCredentials(ref credui,
            authError,
            ref authPackage,
            IntPtr.Zero,
            0,
            out outCredBuffer,
            out outCredSize,
            ref save,
            CREDUIWIN_ENUMERATE_CURRENT_USER);
            if (result != 0) break;
            var usernameBuf = new StringBuilder(100);
            var keyBuf = new StringBuilder(100);
            var domainBuf = new StringBuilder(100);
            var maxUserName = 100;
            var maxDomain = 100;
            var maxKey = 100;
            if (CredUnPackAuthenticationBuffer(1, outCredBuffer, outCredSize, usernameBuf, ref maxUserName, domainBuf, ref maxDomain, keyBuf, ref maxKey))
            {
                Marshal.ZeroFreeCoTaskMemUnicode(outCredBuffer);
                var key = new SecureString();
                foreach (char c in keyBuf.ToString())
                {
                    key.AppendChar(c);
                }
                keyBuf.Clear();
                key.MakeReadOnly();
                psCreds = new PSCredential(usernameBuf.ToString(), key);
                GC.Collect();
                break;
            }

            else authError = 1326; //1326 = 'Logon failure: unknown user name or bad password.'
        }
        return psCreds;
    }
}
"@

    Add-Type -TypeDefinition $Code -Language CSharp

    Write-Output ([Credentials]::getPSCred())
}

Function Get-RunspaceData {
    [cmdletbinding()]
    param(
        [System.Collections.ArrayList]$Runspaces,

        [switch]$Wait,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Cisco", "Remote")]
        [String]$Usage
    )
    $RunspacesCount = ($Runspaces | Measure-Object).Count
    $RunspacesCompleteCount = 0

    Do {
        $more = $false
        Foreach ($runspace in $runspaces) {
            If ($runspace.Runspace.isCompleted) {
                $runspace.Job.EndInvoke($runspace.Runspace)
                $runspace.Thread.Streams.Output | Write-Output
                $runspace.Job.dispose()
                $runspace.Runspace = $null
                $runspace.Job = $null
            }
            ElseIf ($null = $runspace.Runspace) {
                $more = $true
            }
        }
        If ($more -AND $PSBoundParameters['Wait']) {
            Start-Sleep -Milliseconds 100
        }
        #Clean out unused runspace jobs
        $temphash = $runspaces.clone()
        $temphash | Where-Object {
            $Null -eq $_.runspace
        } | ForEach-Object {
            $RunspacesCompleteCount++
            $Runspaces.remove($_)
        }

        Switch ($Usage) {
            "Cisco" {
                Write-Progress -Activity "Running Cisco Config Scans: $ProgressActivity" -Status ("Completed Evaluate-STIG Jobs: {0} of $RunspacesCount" -f $($RunspacesCount - ($Runspaces | Measure-Object).Count)) -PercentComplete ($RunspacesCompleteCount / $RunspacesCount * 100) -CurrentOperation "Remaining: $($Runspaces.Hostname -join ", ")"
            }
            "Remote" {
                $RunningRunspaces = @((Get-Runspace | Where-Object RunspaceStateInfo -notlike "*Closed*").ConnectionInfo.ComputerName | Sort-Object -Unique | ForEach-Object { ($_).Split('.')[0] })
                Write-Progress -Activity "Running Remote Scans: $ProgressActivity" -Status ("Completed Evaluate-STIG Jobs: {0} of $RunspacesCount" -f $($RunspacesCount - ($Runspaces | Measure-Object).Count)) -PercentComplete ($RunspacesCompleteCount / $RunspacesCount * 100) -CurrentOperation "Scanning: $RunningRunspaces"
            }
        }
    } while ($more -AND $PSBoundParameters['Wait'])

    Switch ($Usage) {
        "Cisco" {
            Write-Progress -Activity "Running Cisco Config Scans: $ProgressActivity" -Completed
        }
        "Remote" {
            Remove-Variable RunningRunspaces
            Write-Progress -Activity "Running Remote Scans: $ProgressActivity" -Completed
        }
    }
}

Function Get-FileEncoding {
    <# http://franckrichard.blogspot.com/2010/08/powershell-get-encoding-file-type.html
    https://community.idera.com/database-tools/powershell/powertips/b/tips/posts/get-text-file-encoding
    http://unicode.org/faq/utf_bom.html
    http://en.wikipedia.org/wiki/Byte_order_mark

    Modified by Dan Ireland March 2021
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        [string]$Path
    )

    $Encoding = "ASCII (no BOM)"

    $BOM = New-Object -TypeName System.Byte[](4)
    $File = New-Object System.IO.FileStream($Path, 'Open', 'Read')
    $null = $File.Read($BOM, 0, 4)
    $File.Close()
    $File.Dispose()

    # EF BB BF (UTF8 with BOM)
    If ($BOM[0] -eq 0xef -and $BOM[1] -eq 0xbb -and $BOM[2] -eq 0xbf -and $BOM[3] -eq 0x23) {
        $Encoding = "UTF-8 with BOM"
    }

    # FE FF  (UTF-16 Big-Endian)
    ElseIf ($BOM[0] -eq 0xfe -and $BOM[1] -eq 0xff) {
        $Encoding = "UTF-16 BE"
    }

    # FF FE  (UTF-16 Little-Endian)
    ElseIf ($BOM[0] -eq 0xff -and $BOM[1] -eq 0xfe) {
        $Encoding = "UTF-16 LE"
    }

    # 00 00 FE FF (UTF32 Big-Endian)
    ElseIf ($BOM[0] -eq 0 -and $BOM[1] -eq 0 -and $BOM[2] -eq 0xfe -and $BOM[3] -eq 0xff) {
        $Encoding = "UTF32 Big-Endian"
    }

    # FE FF 00 00 (UTF32 Little-Endian)
    ElseIf ($BOM[0] -eq 0xfe -and $BOM[1] -eq 0xff -and $BOM[2] -eq 0 -and $BOM[3] -eq 0) {
        $Encoding = "UTF32 Little-Endian"
    }

    # 2B 2F 76 (38 | 38 | 2B | 2F)
    ElseIf ($BOM[0] -eq 0x2b -and $BOM[1] -eq 0x2f -and $BOM[2] -eq 0x76 -and ($BOM[3] -eq 0x38 -or $BOM[3] -eq 0x39 -or $BOM[3] -eq 0x2b -or $BOM[3] -eq 0x2f)) {
        $Encoding = "UTF7"
    }

    # F7 64 4C (UTF-1)
    ElseIf ($BOM[0] -eq 0xf7 -and $BOM[1] -eq 0x64 -and $BOM[2] -eq 0x4c ) {
        $Encoding = "UTF-1"
    }

    # DD 73 66 73 (UTF-EBCDIC)
    ElseIf ($BOM[0] -eq 0xdd -and $BOM[1] -eq 0x73 -and $BOM[2] -eq 0x66 -and $BOM[3] -eq 0x73) {
        $Encoding = "UTF-EBCDIC"
    }

    # 0E FE FF (SCSU)
    ElseIf ( $BOM[0] -eq 0x0e -and $BOM[1] -eq 0xfe -and $BOM[2] -eq 0xff ) {
        $Encoding = "SCSU"
    }

    # FB EE 28  (BOCU-1)
    ElseIf ( $BOM[0] -eq 0xfb -and $BOM[1] -eq 0xee -and $BOM[2] -eq 0x28 ) {
        $Encoding = "BOCU-1"
    }

    # 84 31 95 33 (GB-18030)
    ElseIf ($BOM[0] -eq 0x84 -and $BOM[1] -eq 0x31 -and $BOM[2] -eq 0x95 -and $BOM[3] -eq 0x33) {
        $Encoding = "GB-18030"
    }

    Return $Encoding
}

Function Initialize-Archiving {
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Compress", "Expand")]
        [String]$Action,

        [Parameter(Mandatory = $true)]
        [String]$Path,

        [Parameter(Mandatory = $true)]
        [String]$DestinationPath,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Fastest", "NoCompression", "Optimal")]
        [String]$CompressionLevel = "Optimal",

        [Parameter(Mandatory = $false)]
        [Switch]$Force,

        [Parameter(Mandatory = $false)]
        [Switch]$Update
    )

    # Create runspace pool to include required modules.
    $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $SessionState.ImportPSModule('Microsoft.PowerShell.Archive')
    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, 1, $SessionState, $Host)
    $RunspacePool.Open()

    Switch ($Action) {
        "Compress" {
            $Command = "Compress-Archive -Path '$Path' -DestinationPath '$DestinationPath' -CompressionLevel $CompressionLevel"
            If ($Force) {
                $Command = $Command + " -Force"
            }
            If ($Update) {
                $Command = $Command + " -Update"
            }
        }
        "Expand" {
            $Command = "Expand-Archive -Path '$Path' -DestinationPath '$DestinationPath'"
            If ($Force) {
                $Command = $Command + " -Force"
            }
        }
    }

    Try {
        $RSCodeText = 'Try {' + $Command + '} Catch {$Result=@{CodeFail=$true;Message=$($_.Exception.Message)}; Return $Result}' | Out-String
        $RSCodeSB = [scriptblock]::Create($RSCodeText)
        $Result = Invoke-CodeWithTimeout -Code $RSCodeSB -Timeout 5 -RunspacePool $RunspacePool
        If ($Result.CodeFail) {
            Throw "CodeFail"
        }
        $RunspacePool.Close()
        $RunspacePool.Dispose()
        Return "Success"
    }
    Catch {
        $RunspacePool.Close()
        $RunspacePool.Dispose()
        Return $Result.Message
    }
}

Function Initialize-FileXferToRemote {
    Param (
        [Parameter(Mandatory = $true)]
        [String] $NETBIOS,

        [Parameter(Mandatory = $true)]
        [String] $RemoteTemp,

        [Parameter(Mandatory = $false)]
        [String] $OutputPath,

        [Parameter(Mandatory = $false)]
        [String] $AFPath,

        [Parameter(Mandatory = $false)]
        [String] $Remote_Log,

        [Parameter(Mandatory = $false)]
        [String] $LogComponent,

        [Parameter(Mandatory = $false)]
        [String] $OSPlatform,

        [Parameter(Mandatory = $false)]
        [String] $RemoteWorkingDir,

        [Parameter(Mandatory = $false)]
        [String] $ScriptRoot,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.Runspaces.PSSession] $Session
    )

    Write-Log $Remote_Log "Copying Evaluate-STIG archive" $LogComponent "Info" -OSPlatform $OSPlatform
    Copy-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath ESCONTENT.ZIP) -Destination $(Join-Path -Path $RemoteTemp -ChildPath \) -Force -ToSession $Session

    Write-Log $Remote_Log "Expanding Evaluate-STIG archive" $LogComponent "Info" -OSPlatform $OSPlatform
    Invoke-Command -ScriptBlock { param($RemoteTemp) Import-Module Microsoft.PowerShell.Archive; $Global:ProgressPreference = 'SilentlyContinue'; Expand-Archive -Path $(Join-Path -Path $RemoteTemp -ChildPath ESCONTENT.ZIP) -DestinationPath $RemoteTemp -Force } -Session $Session -ArgumentList $RemoteTemp

    If (($AFPath.TrimEnd('\')).TrimEnd('/') -ne (Join-Path -Path $ScriptRoot -ChildPath "AnswerFiles")) {
        Write-Log $Remote_Log "Copying answer file archive" $LogComponent "Info" -OSPlatform $OSPlatform
        Invoke-Command -ScriptBlock { param($RemoteTemp) Remove-Item -Path $(Join-Path -Path $RemoteTemp -ChildPath AnswerFiles | Join-Path -ChildPath *.xml) -Force } -Session $Session -ArgumentList $RemoteTemp
        Copy-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath AFILES.ZIP) -Destination $(Join-Path -Path $RemoteTemp -ChildPath \) -Force -ToSession $Session

        Write-Log $Remote_Log "Expanding answer file archive" $LogComponent "Info" -OSPlatform $OSPlatform
        Invoke-Command -ScriptBlock { param($RemoteTemp) $Global:ProgressPreference = 'SilentlyContinue'; Expand-Archive -Path $(Join-Path -Path $RemoteTemp -ChildPath AFILES.ZIP) -DestinationPath $(Join-Path -Path $RemoteTemp -ChildPath AnswerFiles) -Force } -Session $Session -ArgumentList $RemoteTemp
    }

    If (Test-Path (Join-Path -Path $OutputPath -ChildPath $NETBIOS)) {
        Write-Log $Remote_Log "Compressing previous scan files" $LogComponent "Info" -OSPlatform $OSPlatform
        $Result = Initialize-Archiving -Action Compress -Path $(Join-Path -Path $OutputPath -ChildPath $NETBIOS) -DestinationPath $(Join-Path -Path $RemoteWorkingDir -ChildPath "PREVIOUS_$($NETBIOS).ZIP") -CompressionLevel Optimal -Force
        If ($Result -ne "Success") {
            Throw $Result
        }

        Write-Log $Remote_Log "Copying previous scan archive" $LogComponent "Info" -OSPlatform $OSPlatform
        Invoke-Command -ScriptBlock { param($RemoteTemp) $Global:ProgressPreference = 'SilentlyContinue'; $null = New-Item -ItemType File -Path $(Join-Path -Path $RemoteTemp -ChildPath PREVIOUS.ZIP) } -Session $Session -ArgumentList $RemoteTemp
        Copy-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "PREVIOUS_$($NETBIOS).ZIP") -Destination $(Join-Path -Path $RemoteTemp -ChildPath PREVIOUS.ZIP) -Force -ToSession $Session
        Remove-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "PREVIOUS_$($NETBIOS).ZIP") -Force

        Write-Log $Remote_Log "Expanding previous scan archive" $LogComponent "Info" -OSPlatform $OSPlatform
        Invoke-Command -ScriptBlock { param($RemoteTemp) $Global:ProgressPreference = 'SilentlyContinue'; Expand-Archive -Path $(Join-Path -Path $RemoteTemp -ChildPath PREVIOUS.ZIP) -DestinationPath $(Join-Path -Path $RemoteTemp -ChildPath STIG_Compliance) -Force } -Session $Session -ArgumentList $RemoteTemp
    }
}

Function Initialize-FileXferFromRemote {
    Param (
        [Parameter(Mandatory = $true)]
        [String] $NETBIOS,

        [Parameter(Mandatory = $true)]
        [String] $RemoteTemp,

        [Parameter(Mandatory = $false)]
        [String] $OutputPath,

        [Parameter(Mandatory = $false)]
        [String] $Remote_Log,

        [Parameter(Mandatory = $false)]
        [String] $LogComponent,

        [Parameter(Mandatory = $false)]
        [String] $OSPlatform,

        [Parameter(Mandatory = $false)]
        [String] $RemoteWorkingDir,

        [Parameter(Mandatory = $false)]
        [String] $ScriptRoot,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.Runspaces.PSSession] $session
    )

    Write-Log $Remote_Log "Compressing Evaluate-STIG results" $LogComponent "Info" -OSPlatform $OSPlatform
    Invoke-Command -ScriptBlock { param($RemoteTemp, $NETBIOS) Compress-Archive -Path $(Join-Path -Path $RemoteTemp -ChildPath STIG_Compliance | Join-Path -ChildPath $NETBIOS) -DestinationPath $(Join-Path -Path $RemoteTemp -ChildPath STIG_Compliance | Join-Path -ChildPath "$($NETBIOS).ZIP") -CompressionLevel Optimal -Force } -Session $Session -ArgumentList $RemoteTemp, $NETBIOS

    Write-Log $Remote_Log "Copying Evaluate-STIG results archive" $LogComponent "Info" -OSPlatform $OSPlatform
    Copy-Item -Path $(Join-Path -Path $RemoteTemp -ChildPath STIG_Compliance | Join-Path -ChildPath "$($NETBIOS).ZIP") -Destination $RemoteWorkingDir -Force -FromSession $Session

    Write-Log $Remote_Log "Expanding Evaluate-STIG results archive to $OutputPath" $LogComponent "Info" -OSPlatform $OSPlatform
    If (Test-Path (Join-Path -Path $OutputPath -ChildPath $NETBIOS)) {
        Remove-Item -Path (Join-Path -Path $OutputPath -ChildPath $NETBIOS) -Recurse -Force
    }

    $Result = Initialize-Archiving -Action Expand -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "$($NETBIOS).ZIP") -DestinationPath $OutputPath -Force
    If ($Result -ne "Success") {
        Throw $Result
    }

    Remove-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "$($NETBIOS).ZIP") -Force
}

Function Test-XmlSignature {
    # Based on code sample from https://stackoverflow.com/questions/56986378/validate-signature-on-signed-xml

    Param (
        [xml]$checkxml,
        [switch]$Force
    )

    # Grab signing certificate from document
    $rawCertBase64 = $checkxml.DocumentElement.Signature.KeyInfo.X509Data.X509Certificate

    If (-not $rawCertBase64) {
        $Valid = 'Unable to locate signing certificate in signed document'
    }
    Else {
        $rawCert = [convert]::FromBase64String($rawCertBase64)
        $signingCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(, $rawCert)

        Add-Type -AssemblyName system.security
        [System.Security.Cryptography.Xml.SignedXml]$signedXml = New-Object System.Security.Cryptography.Xml.SignedXml -ArgumentList $checkxml
        $XmlNodeList = $checkxml.GetElementsByTagName("Signature")
        If ($XmlNodeList[0]) {
            $signedXml.LoadXml([System.Xml.XmlElement] ($XmlNodeList[0]))
            $Valid = $signedXml.CheckSignature($signingCertificate, $Force)
        }
        Else {
            $Valid = 'Unable to locate signature in signed document'
        }
    }
    Return $Valid
}

Function Test-XmlValidation {
    # Based on code samples from https://stackoverflow.com/questions/822907/how-do-i-use-powershell-to-validate-xml-files-against-an-xsd

    Param (
        [Parameter(Mandatory = $true)]
        [String] $XmlFile,

        [Parameter(Mandatory = $true)]
        [String] $SchemaFile
    )

    Try {
        Get-ChildItem $XmlFile -ErrorAction Stop | Out-Null
        Get-ChildItem $SchemaFile -ErrorAction Stop | Out-Null

        $XmlErrors = New-Object System.Collections.Generic.List[System.Object]
        [Scriptblock] $ValidationEventHandler = {
            If ($_.Exception.LineNumber) {
                $Message = "$($_.Exception.Message) Line $($_.Exception.LineNumber), position $($_.Exception.LinePosition)."
            }
            Else {
                $Message = ($_.Exception.Message)
            }

            $NewObj = [PSCustomObject]@{
                Message = $Message
            }
            $XmlErrors.Add($NewObj)
        }

        $ReaderSettings = New-Object -TypeName System.Xml.XmlReaderSettings
        $ReaderSettings.ValidationType = [System.Xml.ValidationType]::Schema
        $ReaderSettings.ValidationFlags = [System.Xml.Schema.XmlSchemaValidationFlags]::ProcessIdentityConstraints -bor [System.Xml.Schema.XmlSchemaValidationFlags]::ProcessSchemaLocation -bor [System.Xml.Schema.XmlSchemaValidationFlags]::ReportValidationWarnings
        $ReaderSettings.Schemas.Add($null, $SchemaFile) | Out-Null
        $readerSettings.add_ValidationEventHandler($ValidationEventHandler)

        Try {
            $Reader = [System.Xml.XmlReader]::Create($XmlFile, $ReaderSettings)
            While ($Reader.Read()) {
            }
        }
        Catch {
            $NewObj = [PSCustomObject]@{
                Message = ($_.Exception.Message)
            }
            $XmlErrors.Add($NewObj)
        }
        Finally {
            $Reader.Close()
        }

        If ($XmlErrors) {
            Return $XmlErrors
        }
        Else {
            Return $true
        }
    }
    Catch {
        Return $_.Exception.Message
        Exit 3
    }
}

Function Invoke-ScanCleanup {
    # Run scan cleanup processes
    Param (
        [Parameter(Mandatory = $true)]
        [String]$WorkingDir,

        [Parameter(Mandatory = $false)]
        [String]$Message,

        [Parameter(Mandatory = $false)]
        [Int]$ExitCode = 0,

        [Parameter(Mandatory = $false)]
        [PSObject]$ErrorData,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Windows", "Linux")]
        [String]$OSPlatform,

        [Parameter(Mandatory = $true)]
        [String]$LogComponent
    )

    $LogPath = Join-Path -Path $WorkingDir -ChildPath "Evaluate-STIG.log"
    $ES_Hive_Tasks = @("Eval-STIG_SaveHive", "Eval-STIG_LoadHive", "Eval-STIG_UnloadHive") # Potential scheduled tasks for user hive actions

    # If a bad exit code, we can't continue.
    If ($ExitCode -ne 0) {
        Write-Log $LogPath "ERROR: $($Message)" $LogComponent "Error" -OSPlatform $OSPlatform
        Write-Log $LogPath "Unable to continue." $LogComponent "Error" -OSPlatform $OSPlatform
        Write-Log $LogPath "    $($ErrorData.InvocationInfo.ScriptName)" $LogComponent "Error" -OSPlatform $OSPlatform
        Write-Log $LogPath "    Line: $($ErrorData.InvocationInfo.ScriptLineNumber)" $LogComponent "Error" -OSPlatform $OSPlatform
        Write-Log $LogPath "    $(($ErrorData.InvocationInfo.Line).Trim())" $LogComponent "Error" -OSPlatform $OSPlatform
        Write-Host "$($Message)" -ForegroundColor Red -BackgroundColor Black
        Write-Host "Unable to continue." -ForegroundColor Red -BackgroundColor Black
    }

    # Platform specific tasks
    Switch ($OSPlatform) {
        "Windows" {
            # Unload temporary user hive
            If (Test-Path Registry::HKU\Evaluate-STIG_UserHive) {
                [System.GC]::Collect()
                Try {
                    Write-Log $LogPath "Unloading hive HKU:\Evaluate-STIG_UserHive" $LogComponent "Info" -OSPlatform $OSPlatform
                    $Result = Start-Process -FilePath REG -ArgumentList "UNLOAD HKU\Evaluate-STIG_UserHive" -Wait -PassThru -WindowStyle Hidden
                    If ($Result.ExitCode -ne 0) {
                        Throw
                    }
                }
                Catch {
                    # REG command failed so attempt to do as SYSTEM
                    Write-Log $LogPath "Failed to unload hive.  Trying as SYSTEM." $LogComponent "Warning" -OSPlatform $OSPlatform
                    Try {
                        $Result = Invoke-TaskAsSYSTEM -TaskName $ES_Hive_Tasks[2] -FilePath REG -ArgumentList "UNLOAD HKU\Evaluate-STIG_UserHive" -MaxRunInMinutes 1
                        If ($Result.LastTaskResult -ne 0) {
                            Throw "Failed to unload user hive."
                        }
                    }
                    Catch {
                        Write-Log $LogPath "ERROR: $($_.Exception.Message)" $LogComponent "Error" -OSPlatform $OSPlatform
                    }
                }
            }
        }
        "Linux"{
            # Place holder for Linux cleanup tasks
        }
    }

    # Remove temporary files
    Try {
        $TempFiles = Get-Item -Path $WorkingDir\* -Exclude Evaluate-STIG.log,Bad_CKL -Force
        If ($TempFiles) {
            Write-Log $LogPath "Removing temporary files" $LogComponent "Info" -OSPlatform $OSPlatform
            ForEach ($Item in $TempFiles) {
                $null = Remove-Item -Path $Item.FullName -Recurse -Force -ErrorAction Stop
            }
        }
    }
    Catch {
        Write-Log $LogPath "ERROR: $($_.Exception.Message)" $LogComponent "Error" -OSPlatform $OSPlatform
    }
}

Function Write-SummaryReport {
    Param (
        [Parameter(Mandatory = $true)]
        [String] $CklPath,

        [Parameter(Mandatory = $true)]
        [String] $OutputPath,

        [Parameter(Mandatory = $true)]
        [String] $ProcessedUser,

        [Parameter(Mandatory = $false)]
        [Switch] $Detail,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Windows", "Linux")]
        [String]$OSPlatform,

        [Parameter(Mandatory = $true)]
        [String] $ScanStartDate,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Unclassified", "Classified")]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [psobject] $DeviceInfo,

        [Parameter(Mandatory = $false)]
        [String]$Marking
    )

    $ResultsFile = Join-Path -Path $OutputPath -ChildPath "SummaryReport.xml"
    [Xml]$SummaryResults = New-Object System.Xml.XmlDocument

    # Create declaration
    $Dec = $SummaryResults.CreateXmlDeclaration("1.0", "UTF-8", $null)
    $SummaryResults.AppendChild($dec) | Out-Null

    # Create Root element
    $Root = $SummaryResults.CreateNode("element", "Summary", $null)

    if ($Marking) {
        $MarkingHeader = $SummaryResults.CreateComment("                                                                                          $Marking                                                                                          ")
        $null = $SummaryResults.InsertBefore($MarkingHeader, $SummaryResults.Summary)
    }

    # Pull hardware data
    If ($DeviceInfo) {
        $ComputerData = [ordered]@{
            Name               = $($DeviceInfo.Hostname)
            Manufacturer       = "Cisco"
            Model              = $($DeviceInfo.Model)
            SerialNumber       = $($DeviceInfo.SerialNumber)
            BIOSVersion        = ""
            OSName             = $($DeviceInfo.CiscoOS)
            OSVersion          = $($DeviceInfo.CiscoOSVer)
            OSArchitecture     = ""
            CPUArchitecture    = ""
            NetworkAdapters    = ""
            DiskDrives         = ""
            DistinguishedName  = ""
            ScannedUserProfile = $ProcessedUser
        }
    }
    Else {
        Switch ($OSPlatform) {
            "Windows" {
                $W32ComputerSystem = Get-CimInstance Win32_ComputerSystem | Select-Object *
                $W32OperatingSystem = Get-CimInstance Win32_OperatingSystem | Select-Object *
                $W32SystemEnclosure = Get-CimInstance Win32_SystemEnclosure | Select-Object *
                $W32BIOS = Get-CimInstance Win32_BIOS | Select-Object *
                $W32Processor = Get-CimInstance Win32_Processor | Select-Object *
                $W32DiskDrive = Get-CimInstance Win32_DiskDrive | Select-Object *
                $W32NetAdapterConfig = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object IPEnabled -EQ $true | Select-Object *
                $DistinguishedName = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine")."Distinguished-Name"
                If (-Not($DistinguishedName)) {
                    $DistinguishedName = "Not a domain member"
                }

                Switch ($W32Processor.Architecture) {
                    "0" {
                        $CPUArchitecture = "x86"
                    }
                    "1" {
                        $CPUArchitecture = "MIPS"
                    }
                    "2" {
                        $CPUArchitecture = "Alpha"
                    }
                    "3" {
                        $CPUArchitecture = "PowerPC"
                    }
                    "5" {
                        $CPUArchitecture = "ARM"
                    }
                    "6" {
                        $CPUArchitecture = "ia64"
                    }
                    "9" {
                        $CPUArchitecture = "x64"
                    }
                }

                $ComputerData = [ordered]@{
                    Name               = $([Environment]::MachineName)
                    Manufacturer       = ($W32ComputerSystem.Manufacturer | Out-String).Trim()
                    Model              = ($W32ComputerSystem.Model | Out-String).Trim()
                    SerialNumber       = ($W32SystemEnclosure.SerialNumber | Out-String).Trim()
                    BIOSVersion        = ($W32BIOS.SMBIOSBIOSVersion | Out-String).Trim()
                    OSName             = ($W32OperatingSystem.Caption | Out-String).Trim()
                    OSVersion          = ($W32OperatingSystem.Version | Out-String).Trim()
                    OSArchitecture     = ($W32OperatingSystem.OSArchitecture | Out-String).Trim()
                    CPUArchitecture    = ($CPUArchitecture | Out-String).Trim()
                    NetworkAdapters    = ($W32NetAdapterConfig | Sort-Object Index | ForEach-Object { @{'Adapter' = [ordered]@{
                                    InterfaceIndex = ($_.InterfaceIndex | Out-String).Trim()
                                    Caption        = ($_.Caption | Out-String).Trim()
                                    MACAddress     = ($_.MACAddress | Out-String).Trim()
                                    IPv4           = ((($_.IPAddress | Where-Object { ($_ -Like "*.*.*.*") }) -join ",") | Out-String).Trim()
                                    IPv6           = ((($_.IPAddress | Where-Object { ($_ -Like "*::*") }) -join ",") | Out-String).Trim()
                                }
                            } }
                    )
                    DiskDrives         = ($W32DiskDrive | Sort-Object Index | ForEach-Object { @{'Disk' = [ordered]@{
                                    Index         = ($_.Index | Out-String).Trim()
                                    DeviceID      = ($_.DeviceID | Out-String).Trim()
                                    Size          = ("$([Math]::Round($_.Size / 1Gb, 2)) GB" | Out-String).Trim()
                                    Caption       = ($_.Caption | Out-String).Trim()
                                    SerialNumber  = ($_.SerialNumber | Out-String).Trim()
                                    MediaType     = ($_.MediaType | Out-String).Trim()
                                    InterfaceType = ($_.InterfaceType | Out-String).Trim()
                                }
                            } }
                    )
                    DistinguishedName  = $DistinguishedName
                    ScannedUserProfile = $ProcessedUser
                }
            }
            "Linux" {
                $W32HostName = [Environment]::MachineName
                $W32ComputerSystem_Manufacturer = (dmidecode | grep -A5 '^System Information' | grep Manufacturer).Trim().replace("Manufacturer: ", "")
                $W32ComputerSystem_Model = (dmidecode | grep -A5 '^System Information' | grep Product).Trim().replace("Product Name: ", "")
                $W32Computersystem_Serial = (dmidecode | grep -A5 '^System Information' | grep Serial).Trim().replace("Serial Number: ", "")
                $W32OperatingSystem_OSName = (Get-Content /etc/os-release | grep "^PRETTY").replace("PRETTY_NAME=", "").replace('"', "")
                $W32OperatingSystem_OSVersion = (Get-Content /etc/os-release | grep "^VERSION_ID").replace("VERSION_ID=", "").replace('"', "")
                $W32OperatingSystem_OSArchitecture = arch
                $W32BIOS_SMBIOSBIOSVersion = (dmidecode | grep -A3 "^BIOS" | grep Version).Trim().replace("Version: ", "")
                $CPUArchitecture = (lscpu | grep "^Architecture").replace("Architecture:", "").Trim()
                $W32NetAdapterConfig = (lshw -C network -short | awk '!(NR<=2) {print $2}')
                $DistinguishedName = "Not a domain member"
                Try {
                    $LVM_Data = @((lvscan).split('[\r\n]+'))
                    $W32DiskDrive = $LVM_Data
                }
                Catch {
                    $Disk_Data = @((lsblk -nlo "NAME,SIZE,MOUNTPOINT").split('[\r\n]+'))
                    $W32DiskDrive = $Disk_Data | ForEach-Object { @{
                            Index    = "'//$($_ | awk '{print $1}')/'"
                            DeviceID = "'//$($_ | awk '{print $3}')'"
                            Size     = "[$($_ | awk '{print $2}')]"
                        }
                    }
                }

                $ComputerData = [ordered]@{
                    Name               = $W32HostName
                    Manufacturer       = ($W32ComputerSystem_Manufacturer | Out-String).Trim()
                    Model              = ($W32ComputerSystem_Model | Out-String).Trim()
                    SerialNumber       = ($W32Computersystem_Serial | Out-String).Trim()
                    BIOSVersion        = ($W32BIOS_SMBIOSBIOSVersion | Out-String).Trim()
                    OSName             = ($W32OperatingSystem_OSName | Out-String).Trim()
                    OSVersion          = ($W32OperatingSystem_OSVersion | Out-String).Trim()
                    OSArchitecture     = ($W32OperatingSystem_OSArchitecture | Out-String).Trim()
                    CPUArchitecture    = ($CPUArchitecture | Out-String).Trim()
                    NetworkAdapters    = ($W32NetAdapterConfig | Sort-Object Index | ForEach-Object { @{'Adapter' = [ordered]@{
                                    InterfaceIndex = (Get-Content /sys/class/net/$_/ifindex)
                                    Caption        = (lshw -C network -short | grep $_ | awk '{print $2}')
                                    MACAddress     = (ip addr show dev $_ | grep "link/ether" | cut -d ' ' -f 6)
                                    IPV4           = (ip -4 addr show dev $_ | grep "inet " | cut -d ' ' -f 6 | cut -f 1 -d '/')
                                    IPV6           = (ip -6 addr show dev $_ | grep "inet " | cut -d ' ' -f 6 | cut -f 1 -d '/')
                                }
                            } }
                    )
                    DiskDrives         = ($W32DiskDrive | Sort-Object Index | ForEach-Object { @{'Disk' = [ordered]@{
                                    Index    = ($_ | cut -d '/' -f 3 | Out-String).Trim()
                                    DeviceID = ($_ | cut -d "'" -f 2 | cut -d '/' -f 4 | Out-String).Trim()
                                    Size     = ($_ | cut -d "]" -f 1 | cut -d "[" -f 2 | Out-String).Trim()
                                }
                            } }
                    )
                    DistinguishedName  = $DistinguishedName
                    ScannedUserProfile = $ProcessedUser
                }
            }
        }
    }

    # Create Computer element
    $Computer = $SummaryResults.CreateNode("element", "Computer", $null)
    $ScanDate = $SummaryResults.CreateNode("element", "ScanDate", $null)
    $EvalSTIGVer = $SummaryResults.CreateNode("element", "EvalSTIGVer", $null)
    $ESScanType = $SummaryResults.CreateNode("element", "ScanType", $null)
    $ScanDate.InnerText = $($ScanStartDate)
    $Computer.AppendChild($ScanDate) | Out-Null
    $EvalSTIGVer.InnerText = $ESVersion
    $Computer.AppendChild($EvalSTIGVer) | Out-Null
    $ESScanType.InnerText = $ScanType
    $Computer.AppendChild($ESScanType) | Out-Null
    if ($Marking) {
        $ESMarking = $SummaryResults.CreateNode("element", "Marking", $null)
        $ESMarking.InnerText = $Marking
        $Computer.AppendChild($ESMarking) | Out-Null
    }
    ForEach ($Key in $ComputerData.GetEnumerator()) {
        $Element = $SummaryResults.CreateNode("element", $($Key.Key), $null)
        If ($Key.Key -eq "NetworkAdapters") {
            ForEach ($Adapter in $ComputerData.NetworkAdapters.Adapter) {
                $NetworkElement = $SummaryResults.CreateNode("element", "Adapter", $null)
                $NetworkElement.SetAttribute("InterfaceIndex", $Adapter.InterfaceIndex)

                $Caption = $SummaryResults.CreateNode("element", "Caption", $null)
                $Caption.InnerText = $Adapter.Caption
                $NetworkElement.AppendChild($Caption) | Out-Null

                $MACAddress = $SummaryResults.CreateNode("element", "MACAddress", $null)
                $MACAddress.InnerText = $Adapter.MACAddress
                $NetworkElement.AppendChild($MACAddress) | Out-Null

                $IPv4Addresses = $SummaryResults.CreateNode("element", "IPv4Addresses", $null)
                $IPv4Addresses.InnerText = $Adapter.IPv4
                $NetworkElement.AppendChild($IPv4Addresses) | Out-Null

                $IPv6Addresses = $SummaryResults.CreateNode("element", "IPv6Addresses", $null)
                $IPv6Addresses.InnerText = $Adapter.IPv6
                $NetworkElement.AppendChild($IPv6Addresses) | Out-Null

                $Element.AppendChild($NetworkElement) | Out-Null
            }
        }
        ElseIf ($Key.Key -eq "DiskDrives") {
            ForEach ($Disk in $ComputerData.DiskDrives.Disk) {
                $DiskElement = $SummaryResults.CreateNode("element", "Disk", $null)
                $DiskElement.SetAttribute("Index", $Disk.Index)

                $DeviceID = $SummaryResults.CreateNode("element", "DeviceID", $null)
                $DeviceID.InnerText = $Disk.DeviceID
                $DiskElement.AppendChild($DeviceID) | Out-Null

                $Size = $SummaryResults.CreateNode("element", "Size", $null)
                $Size.InnerText = $Disk.Size
                $DiskElement.AppendChild($Size) | Out-Null

                $Caption = $SummaryResults.CreateNode("element", "Caption", $null)
                $Caption.InnerText = $Disk.Caption
                $DiskElement.AppendChild($Caption) | Out-Null

                $SerialNumber = $SummaryResults.CreateNode("element", "SerialNumber", $null)
                $SerialNumber.InnerText = $Disk.SerialNumber
                $DiskElement.AppendChild($SerialNumber) | Out-Null

                $MediaType = $SummaryResults.CreateNode("element", "MediaType", $null)
                $MediaType.InnerText = $Disk.MediaType
                $DiskElement.AppendChild($MediaType) | Out-Null

                $InterfaceType = $SummaryResults.CreateNode("element", "InterfaceType", $null)
                $InterfaceType.InnerText = $Disk.InterfaceType
                $DiskElement.AppendChild($InterfaceType) | Out-Null

                $Element.AppendChild($DiskElement) | Out-Null
            }
        }
        Else {
            $Element.InnerText = ($Key.Value)
        }
        $Computer.AppendChild($Element) | Out-Null
    }
    $Root.AppendChild($Computer) | Out-Null

    # Create Checklists element
    $Checklists = $SummaryResults.CreateNode("element", "Checklists", $null)

    $CklList = Get-ChildItem -Path $CklPath -Filter *.ckl
    ForEach ($Ckl in $CklList) {
        $CklData = Get-CklData -CklFile $Ckl.Fullname
        $STIGName = ($CklData | Select-Object STIG -Unique).STIG

        # Create node for checklist
        $CklNode = $SummaryResults.CreateNode("element", "Checklist", $null)
        $CklNode.SetAttribute("CklFile", $Ckl.Name) | Out-Null
        $CKLNode.SetAttribute("Date", $CKL.LastWriteTime.ToString("yyyy-MM-dd HH:mm")) | Out-Null

        # Create and populate STIG element
        $STIG = $SummaryResults.CreateNode("element", "STIG", $null)
        $STIG.InnerText = $STIGName
        $CklNode.AppendChild($STIG) | Out-Null

        $CatList = @("CAT_I", "CAT_II", "CAT_III")
        ForEach ($Cat in $CatList) {
            # Create CAT node
            $CatNode = $SummaryResults.CreateNode("element", $Cat, $null)

            # Get CAT I checks
            [hashtable]$StatusTotals = @{ }
            $AllCat = $CklData | Where-Object Severity -EQ $Cat
            $StatusTotals.NotReviewed = ($AllCat | Where-Object Status -EQ "Not_Reviewed" | Measure-Object).Count
            $StatusTotals.NotAFinding = ($AllCat | Where-Object Status -EQ "NotAFinding" | Measure-Object).Count
            $StatusTotals.Open = ($AllCat | Where-Object Status -EQ "Open" | Measure-Object).Count
            $StatusTotals.Not_Applicable = ($AllCat | Where-Object Status -EQ "Not_Applicable" | Measure-Object).Count
            $StatusTotals.Total = ($AllCat | Measure-Object).Count

            # Populate CAT node
            $CatNode.SetAttribute("Total", $StatusTotals.Total) | Out-Null
            $CatNode.SetAttribute("Not_Applicable", $StatusTotals.Not_Applicable) | Out-Null
            $CatNode.SetAttribute("Open", $StatusTotals.Open) | Out-Null
            $CatNode.SetAttribute("NotAFinding", $StatusTotals.NotAFinding) | Out-Null
            $CatNode.SetAttribute("NotReviewed", $StatusTotals.NotReviewed) | Out-Null

            If ($Detail) {
                # Create Vuln node and populate
                ForEach ($Vuln in $AllCat) {
                    $VulnNode = $SummaryResults.CreateNode("element", "Vuln", $null)
                    $VulnNode.SetAttribute("RuleTitle", $Vuln.RuleTitle) | Out-Null
                    $VulnNode.SetAttribute("Status", $Vuln.Status) | Out-Null
                    $VulnNode.SetAttribute("ID", $Vuln.VulnID) | Out-Null
                    $CatNode.AppendChild($VulnNode) | Out-Null
                }
            }
            $CklNode.AppendChild($CatNode) | Out-Null
        }
        $Checklists.AppendChild($CklNode) | Out-Null
    }

    $Root.AppendChild($Checklists) | Out-Null
    $SummaryResults.AppendChild($Root) | Out-Null
    if ($Marking) {
        $MarkingFooter = $SummaryResults.CreateComment("                                                                                          $Marking                                                                                          ")
        $null = $SummaryResults.InsertAfter($MarkingFooter, $SummaryResults.Summary)
    }
    $SummaryResults.Save($ResultsFile)
}

Function Get-IniContent ($FilePath) {
    $Ini = @{ }
    Switch -Regex -File $FilePath {
        "^\[(.+)\]" {
            # Section
            $Section = $Matches[1]
            $Ini[$Section] = @{ }
            $CommentCount = 0
        }
        "^(;.*)$" {
            # Comment
            $Value = $Matches[1]
            $CommentCount = $CommentCount + 1
            $Name = "Comment" + $CommentCount
            If ($Section) {
                $Ini[$Section][$Name] = $Value
            }
            Else {
                $Ini[$Name] = $Value
            }
        }
        "(.+?)\s*=\s*(.*)" {
            # Key
            $Name, $Value = $Matches[1..2]
            If ($Section) {
                $Ini[$Section][$Name] = $Value
            }
            Else {
                $Ini[$Name] = $Value
            }
        }
    }
    Return $Ini
}

Function Get-UsersToEval {
    [cmdletbinding()]
    Param (
        [Switch]$ProvideSingleUser
    )

    $ProfileList = New-Object System.Collections.Generic.List[System.Object]
    $UserProfiles = Get-CimInstance Win32_UserProfile | Where-Object LocalPath -NotLike "$($env:Windir)*" | Select-Object SID, LocalPath, LastuseTime

    # Iterate through Profiles to pull required data
    ForEach ($Profile in $UserProfiles) {
        $ErrorActionPreference = "SilentlyContinue"
        $Preferred = $false
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($Profile.SID)
        Try {
            $Username = ($objSID.Translate([System.Security.Principal.NTAccount])).Value
            $NTUserPol = @()
            If (Test-Path "$env:ProgramData\Microsoft\GroupPolicy\Users\$($Profile.SID)\ntuser.pol") {
                $NTUserPol += Get-ChildItem -Path "$env:ProgramData\Microsoft\GroupPolicy\Users\$($Profile.SID)\ntuser.pol" -Force
            }
            If (Test-Path "$($Profile.LocalPath)\ntuser.pol") {
                $NTUserPol += Get-ChildItem -Path "$($Profile.LocalPath)\ntuser.pol" -Force
            }

            If (($NTUserPol | Measure-Object).Count -gt 0) {
                $LastPolicyUpdate = ($NtuserPol | Sort-Object LastWriteTime -Descending)[0].LastWriteTime
            }
            Else {
                $LastPolicyUpdate = "Never"
            }

            If ($Username -match " ") {
                $Username = [Char]34 + $Username + [Char]34
            }

            $LocalPath = $Profile.LocalPath

            If (($UserName.Split("\")[0] -ne $([Environment]::MachineName)) -and ($LastPolicyUpdate -ne "Never" -and (New-TimeSpan -Start $LastPolicyUpdate -End (Get-Date)).Days -le 14)) {
                $Preferred = $true
            }

            $NewObj = [PSCustomObject]@{
                Username         = $Username
                LastPolicyUpdate = $LastPolicyUpdate
                SID              = $objSID.Value
                LocalPath        = $LocalPath
                LastUseTime      = $Profile.LastUseTime
                Preferred        = $Preferred
            }
            $ProfileList.Add($NewObj)
            $ErrorActionPreference = "Continue"
        }
        Catch {
            { Write-Error } | Out-Null
        }
    }

    If ($ProfileList | Where-Object LastPolicyUpdate -NE "Never") {
        $ProfileList = ($ProfileList | Where-Object LastPolicyUpdate -NE "Never" | Sort-Object Preferred, LastPolicyUpdate -Descending)
    }
    Else {
        $ProfileList = ($ProfileList | Sort-Object LastUseTime -Descending)
    }

    If ($ProvideSingleUser) {
        $UserToProcess = $ProfileList[0]
        Return $UserToProcess
    }
    Else {
        Return $ProfileList
    }
}


Function Get-GroupMembership ($Group) {
    $GroupMembers = New-Object System.Collections.Generic.List[System.Object]

    $Computer = [ADSI]"WinNT://$env:COMPUTERNAME,Computer"
    $Object = $Computer.psbase.Children | Where-Object { $_.psbase.schemaClassName -eq "group" -and $_.Name -eq $Group }
    ForEach ($Item In $Object) {
        $Members = @($Item.psbase.Invoke("Members"))
        ForEach ($Member In $Members) {
            $ObjectSID = $Member.GetType().InvokeMember("objectSid", 'GetProperty', $Null, $Member, $Null)
            $Name = ($Member.GetType().InvokeMember("AdsPath", 'GetProperty', $Null, $Member, $Null))
            If ($Name -match $env:COMPUTERNAME) {
                $Name = "$env:COMPUTERNAME" + (($Name -Split $env:COMPUTERNAME)[1]).Replace("/", "\")
            }
            Else {
                $Name = ($Name).Replace("WinNT://", "").Replace("/", "\")
            }
            $NewObj = [PSCustomObject]@{
                Name        = $Name
                ObjectClass = $Member.GetType().InvokeMember("Class", 'GetProperty', $Null, $Member, $Null)
                SID         = (New-Object System.Security.Principal.SecurityIdentifier($objectSID, 0)).Value
            }
            $GroupMembers.Add($NewObj)
        }
    }

    Return $GroupMembers
}

Function Invoke-CodeWithTimeout {
    Param
    (
        [Parameter(Mandatory)]
        [ScriptBlock]$Code,

        [Parameter(Mandatory)]
        [int]$Timeout,

        [Parameter(Mandatory)]
        $RunspacePool
    )

    $ps = [PowerShell]::Create()
    $ps.Runspacepool = $RunspacePool
    $null = $ps.AddScript($Code)
    $handle = $ps.BeginInvoke()
    $start = Get-Date
    do {
        $timeConsumed = (Get-Date) - $start
        if ($timeConsumed.TotalMinutes -ge $Timeout) {
            $ps.Stop()
            $ps.Dispose()
            throw "Job timed out."
        }
        Start-Sleep -Milliseconds 50
    } until ($handle.isCompleted)

    $ps.EndInvoke($handle)
    $ps.Dispose()
}

Function Write-Ckl {
    # Create a STIG checklist from a blank .ckl file
    Param (
        [Parameter(Mandatory = $true)]
        [String]$STIGName,

        [Parameter(Mandatory = $true)]
        [String]$ShortName,

        [Parameter(Mandatory = $true)]
        [String]$TemplateName,

        [Parameter(Mandatory = $true)]
        [String]$CklSourcePath,

        [Parameter(Mandatory = $true)]
        [String]$ModulesPath,

        [Parameter(Mandatory = $true)]
        [String]$CklDestinationPath,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String] $ScanStartDate,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$Marking,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$VulnTimeout,

        [Parameter(Mandatory = $false)]
        [Switch]$NoPrevious,

        [Parameter(Mandatory = $false)]
        [Array]$SelectVuln,

        [Parameter(Mandatory = $false)]
        [Array]$ExcludeVuln,

        [Parameter(Mandatory = $false)]
        [String]$PsModule,

        [Parameter(Mandatory = $false)]
        [String]$WorkingDir,

        [Parameter(Mandatory = $true)]
        [String]$Checklist_xsd,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Web", "DB")]
        [String]$WebOrDB,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Windows", "Linux")]
        [String]$OSPlatform,

        [Parameter(Mandatory = $false)]
        [Int]$ProgressId,

        [Parameter(Mandatory = $false)]
        [Int]$TotalSubSteps,

        [Parameter(Mandatory = $false)]
        [Int]$CurrentSubStep,

        [Parameter(Mandatory = $false)]
        [psobject]$InstalledO365Apps,

        [Parameter(Mandatory = $false)]
        [String]$Site,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [psobject]$ApacheInstance,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [psobject]$VirtualHost,

        [Parameter(Mandatory = $false)]
        [psobject]$PGInstance,

        [Parameter(Mandatory = $false)]
        [psobject]$EnsConfig,

        [Parameter(Mandatory = $false)]
        [psobject]$ShowTech,

        [Parameter(Mandatory = $false)]
        [psobject]$ShowRunningConfig,

        [Parameter(Mandatory = $false)]
        [psobject]$DeviceInfo
    )

    Process {
        $LogPath = Join-Path -Path $WorkingDir -ChildPath "Evaluate-STIG.log"
        $CheckFail = $false # Us this to determine if a check resulted in an error so that main script can take action.

        # Read the CKL template.
        $NewCKL = (Select-Xml -XPath / -Path (Join-Path -Path $CklSourcePath -ChildPath $TemplateName)).Node #this method of loading xml preserves whitespace and handles encoding (e.g. UTF-8)
        if ($Marking) {
            $MarkingHeader = $NewCKL.CreateComment("                                                                                          $Marking                                                                                          ")
            $null = $NewCKL.InsertBefore($MarkingHeader, $NewCKL.CHECKLIST)
        }

        #Add STIGMAN data to CKL
        $ESVersionXML = $NewCKL.CreateComment("<Evaluate-STIG><global><version>$ESVersion</version><time>$(Get-Date -Format 'o')</time></global><module><name>$PSModule</name><version>$((Get-Module $PSModule).Version)</version></module><stiglist><name>$STIGName</name><shortname>$ShortName</shortname><template>$TemplateName</template></stiglist></Evaluate-STIG>")
        $null = $NewCKL.InsertBefore($ESVersionXML, $NewCKL.CHECKLIST)

        # Get STIG Version/Release data from the  CKL template
        $STIGVer = ([regex]::Match(($NewCKL.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA | Where-Object SID_NAME -EQ "filename").SID_DATA, 'V\dR\d\S').Value).Replace("_", "")

        # Basic things needed to fill out the checklist
        If ($ShowTech) {
            $MachineName = $DeviceInfo.Hostname
            $RouterIPs = (((Get-Section $ShowRunningConfig "interface loopback0" | Select-String -Pattern "ip address" | Out-String).Trim()).Replace("ip address ", "")).Split([char[]]"")[0]
            If (-Not($RouterIPs -match "\d+\.\d+\.\d+\.\d+")) {
                $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
                $RouterIPs = @()
                ForEach ($Interface in $Interfaces) {
                    $IP = (((Get-Section $ShowRunningConfig $Interface | Select-String -Pattern "ip address" | Out-String).Trim()).Replace("ip address ", "")).Split([char[]]"")[0]
                    If ($IP -match "\d+\.\d+\.\d+\.\d+") {
                        $RouterIPs += $IP
                    }
                }
            }
            $IPAddress = $RouterIPs -join ", "
            $Role = "None"
            $MACAddress = $DeviceInfo.MACAddress
            If ($DeviceInfo.Hostname -and $DeviceInfo.DomainName) {
                $FQDN = "$($DeviceInfo.Hostname).$($DeviceInfo.DomainName)"
            }
            Else {
                $FQDN = ""
            }

            If (-Not(Test-Path $WorkingDir)) {
                $null = New-Item -Path $WorkingDir -ItemType Directory -ErrorAction Stop
            }
            $LogPath = Join-Path -Path $WorkingDir -ChildPath "Evaluate-STIG.log"
        }
        Else {
            $LogPath = Join-Path -Path $WorkingDir -ChildPath "Evaluate-STIG.log"
            $MachineName = ([Environment]::MachineName).ToUpper()
            Switch ($OSPlatform) {
                "Windows" {
                    $NetAdapter = Get-CimInstance -Namespace root\cimv2 -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | Sort-Object Index
                    $IPAddress = ($NetAdapter.IPAddress -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}") -join ", "
                    $MACAddress = ($NetAdapter.MACAddress) -join ", "
                    $FQDN = ("$((Get-CimInstance -Namespace root\cimv2 -ClassName Win32_ComputerSystem).DNSHostName).$((Get-CimInstance -Namespace root\cimv2 -ClassName Win32_ComputerSystem).Domain)").ToLower()

                    Switch ((Get-CimInstance Win32_ComputerSystem).DomainRole) {
                        { $_ -eq 1 } {
                            $Role = "Workstation"
                        }
                        { $_ -eq 3 } {
                            $Role = "Member Server"
                        }
                        { ($_ -eq 4) -or ($_ -eq 5) } {
                            $Role = "Domain Controller"
                        }
                        Default {
                            $Role = "None"
                        }
                    }
                }
                "Linux" {
                    $Release = ""
                    $Role = ""
                    if ((Get-Content /etc/os-release) -like '*VERSION_ID="8.*') {
                        $release = "Workstation"
                    }
                    else {
                        $release = (Get-Content /etc/os-release | egrep -i "VARIANT=|^ID=").replace("VARIANT=", "").replace('"', "").replace("ID=", "").replace("rhel", "") | Where-Object { $_ -ne "" }
                    }
                    switch ($release) {
                        {($_ -in @("Workstation","ubuntu"))} {
                            $Role = "Workstation"
                        }
                        "Server" {
                            $Role = "Member Server"
                        }
                        default {
                            $Role = "None"
                        }
                    }

                    (lshw -C network -short | awk '!(NR<=2) {print $2}') | ForEach-Object { if ((Get-Content /sys/class/net/$_/operstate) -eq "up") {
                            $NetAdapter = $_
                        } }
                    $IPAddress = (ip -4 addr show dev $NetAdapter | grep "inet " | cut -d ' ' -f 6 | cut -f 1 -d '/')
                    $MACAddress = (ip addr show dev $NetAdapter | grep "link/ether" | cut -d ' ' -f 6)
                    $FQDN = hostname --fqdn
                }
            }
        }

        If (Test-Path -Path (Join-Path -Path $CklSourcePath -ChildPath $TemplateName)) {
            If ((Get-Item -Path (Join-Path -Path $CklSourcePath -ChildPath $TemplateName)).Extension -ne ".ckl") {
                Write-Log $LogPath "Source template must be a .ckl file" $LogComponent "Error" -OSPlatform $OSPlatform
            }
            Else {
                $TemplateFile = (Get-Item -Path (Join-Path -Path $CklSourcePath -ChildPath $TemplateName)).BaseName
            }
        }
        Else {
            Write-Log $LogPath "Failed to find template." $LogComponent "Error" -OSPlatform $OSPlatform
            Exit 1
        }

        # Set Checklist file name
        $Date = Get-Date -Format "yyyyMMdd-HHmmss"
        If ($WebOrDB) {
            Switch ($WebOrDB) {
                "Web" {
                    If ($IsLinux) {
                        $CklOutFile = "$($MachineName)_$($TemplateFile)_$($PSBoundParameters.Site)_$($STIGVer)_$($Date).ckl"
                    }
                    Else {
                        $CklOutFile = "$($MachineName)_$($TemplateFile)_($($PSBoundParameters.Site))_$($STIGVer)_$($Date).ckl"
                    }
                }
                "DB" {
                    If ($TemplateName -like "*SQL*Instance*") {
                        If ($IsLinux) {
                            $CklOutFile = "$($MachineName)_$($TemplateFile)_$($Instance.replace("\","-"))_$($STIGVer)_$($Date).ckl"
                        }
                        Else {
                            $CklOutFile = "$($MachineName)_$($TemplateFile)_($($Instance.replace("\","-")))_$($STIGVer)_$($Date).ckl"
                        }
                    }
                    ElseIf ($TemplateName -like "*SQL*DB*") {
                        If ($IsLinux) {
                            $CklOutFile = "$($MachineName)_$($TemplateFile)_$($Instance.replace("\","-"))_$($Database)_$($STIGVer)_$($Date).ckl"
                        }
                        Else {
                            $CklOutFile = "$($MachineName)_$($TemplateFile)_($($Instance.replace("\","-"))_$($Database))_$($STIGVer)_$($Date).ckl"
                        }
                    }
                    ElseIf ($TemplateName -like "*Pg*9x*") {
                        If ($IsLinux) {
                            $CklOutFile = "$($MachineName)_$($TemplateFile)_$($Instance)_$($Database)_$($STIGVer)_$($Date).ckl"
                        }
                        Else {
                            $CklOutFile = "$($MachineName)_$($TemplateFile)_($($Instance)_$($Database))_$($STIGVer)_$($Date).ckl"
                        }
                    }
                }
            }
        }
        Else {
            $CklOutFile = "$($MachineName)_$($TemplateFile)_$($STIGVer)_$($Date).ckl"
        }

        if ($SelectVuln) {
            $CklOutFile = "Partial_$CKLOutFile"
        }
        Write-Log $LogPath "Output CKL file:  $($CklOutFile)" $LogComponent "Info" -OSPlatform $OSPlatform

        # Create the resulting xml file that is to be turned into a ckl for STIG Viewer
        $CklOutPath = Join-Path -Path $WorkingDir -ChildPath "Checklist" | Join-Path -ChildPath $CklOutFile
        New-Item $CklOutPath -ItemType File -Force | Out-Null
        $ResultFile = Get-Item $CklOutPath

        # Update asset info in checklist
        $NewCKL.CHECKLIST.ASSET.ROLE = [string]$Role
        $NewCKL.CHECKLIST.ASSET.HOST_NAME = [string]$MachineName
        $NewCKL.CHECKLIST.ASSET.HOST_IP = [string]$IPAddress
        $NewCKL.CHECKLIST.ASSET.HOST_MAC = [string]$MACAddress
        $NewCKL.CHECKLIST.ASSET.HOST_FQDN = [string]$FQDN
        $NewCKL.CHECKLIST.ASSET.MARKING = [string]$Marking
        If ($WebOrDB) {
            $NewCKL.CHECKLIST.ASSET.WEB_OR_DATABASE = [string]"true"
            Switch ($WebOrDB) {
                "Web" {
                    $NewCKL.CHECKLIST.ASSET.WEB_DB_SITE = [string]$PSBoundParameters.Site
                }
                "DB" {
                    if ($TemplateName -like "*Pg*9x*") {
                        $NewCKL.CHECKLIST.ASSET.WEB_DB_SITE = [string]"$($Instance)"
                        $NewCKL.CHECKLIST.ASSET.WEB_DB_INSTANCE = [string]"$($Database)"
                    }
                    else {
                        $Host_Instance = $Instance.Split("\")
                        $NewCKL.CHECKLIST.ASSET.WEB_DB_SITE = [string]$Host_Instance[0]
                        Switch (($NewCKL.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA | Where-Object SID_NAME -EQ stigid).SID_DATA) {
                            { $_ -like "*Instance*" } {
                                $NewCKL.CHECKLIST.ASSET.WEB_DB_INSTANCE = [string]$Host_Instance[1]
                            }
                            { $_ -like "*Database*" } {
                                $NewCKL.CHECKLIST.ASSET.WEB_DB_INSTANCE = [string]"$($Host_Instance[1])_$($Database)"
                            }
                        }
                    }
                }
            }
        }

        # Look for a previous CKL for potential administrator comments
        $STIGID = ($NewCKL.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA | Where-Object SID_NAME -EQ "stigid").SID_DATA
        $OldCKLFileList = @()
        ForEach ($Item in (Get-ChildItem -Path $CklDestinationPath | Where-Object Extension -EQ ".ckl" | Sort-Object LastWriteTime -Descending)) {
            $PreCKL_STIGID = ((Select-Xml -Path $Item.FullName -XPath "CHECKLIST/STIGS/iSTIG/STIG_INFO/SI_DATA").Node | Where-Object SID_NAME -EQ "stigid").SID_DATA
            $PreCKL_HOST_NAME = ((Select-Xml -Path $Item.FullName -XPath "CHECKLIST/ASSET").Node).HOST_NAME
            $PreCKL_WEB_OR_DATABASE = ((Select-Xml -Path $Item.FullName -XPath "CHECKLIST/ASSET").Node).WEB_OR_DATABASE
            $PreCKL_WEB_DB_SITE = ((Select-Xml -Path $Item.FullName -XPath "CHECKLIST/ASSET").Node).WEB_DB_SITE
            $PreCKL_WEB_DB_INSTANCE = ((Select-Xml -Path $Item.FullName -XPath "CHECKLIST/ASSET").Node).WEB_DB_INSTANCE

            If (($PreCKL_STIGID -eq $STIGID) -and ($PreCKL_HOST_NAME -eq $NewCKL.CHECKLIST.ASSET.HOST_NAME) -and ($PreCKL_WEB_OR_DATABASE -eq $NewCKL.CHECKLIST.ASSET.WEB_OR_DATABASE) -and ($PreCKL_WEB_DB_SITE -eq $NewCKL.CHECKLIST.ASSET.WEB_DB_SITE) -and ($PreCKL_WEB_DB_INSTANCE -eq $NewCKL.CHECKLIST.ASSET.WEB_DB_INSTANCE)) {
                $OldCKLFileList += $Item
            }
        }
        If ($OldCKLFileList) {
            Write-Log $LogPath "Found previous checklist file: $($OldCKLFileList[0].Name).  Loading into memory to preserve any required administrator comments." $LogComponent "Info" -OSPlatform $OSPlatform
            $OldCKL = (Select-Xml -XPath / -Path $OldCKLFileList[0].FullName).Node
        }

        # If a PsModule exists, import the available commands to a variable.  This reduces scan times.
        If ($PsModule) {
            $PsModuleCommands = Get-Command -Module $PsModule
        }

        # Create global variable objects that need passed to runspace session
        $GlobalVars = @{
            1  = [System.Management.Automation.Runspaces.SessionStateVariableEntry]::new("LogPath", $LogPath, "", [System.Management.Automation.ScopedItemOptions]::AllScope)
            2  = [System.Management.Automation.Runspaces.SessionStateVariableEntry]::new("LogComponent", $LogComponent, "", [System.Management.Automation.ScopedItemOptions]::AllScope)
            3  = [System.Management.Automation.Runspaces.SessionStateVariableEntry]::new("OSPlatform", $OSPlatform, "", [System.Management.Automation.ScopedItemOptions]::AllScope)
            4  = [System.Management.Automation.Runspaces.SessionStateVariableEntry]::new("ESVersion", $ESVersion, "", [System.Management.Automation.ScopedItemOptions]::AllScope)
            5  = [System.Management.Automation.Runspaces.SessionStateVariableEntry]::new("ScanStartDate", $ScanStartDate, "", [System.Management.Automation.ScopedItemOptions]::AllScope)
            6  = [System.Management.Automation.Runspaces.SessionStateVariableEntry]::new("PGInstance", $PGInstance, "", [System.Management.Automation.ScopedItemOptions]::AllScope)
            7  = [System.Management.Automation.Runspaces.SessionStateVariableEntry]::new("ApacheInstance", $ApacheInstance, "", [System.Management.Automation.ScopedItemOptions]::AllScope)
            8  = [System.Management.Automation.Runspaces.SessionStateVariableEntry]::new("VirtualHost", $VirtualHost, "", [System.Management.Automation.ScopedItemOptions]::AllScope)
            9  = [System.Management.Automation.Runspaces.SessionStateVariableEntry]::new("EnsConfig", $EnsConfig, "", [System.Management.Automation.ScopedItemOptions]::AllScope)
            10 = [System.Management.Automation.Runspaces.SessionStateVariableEntry]::new("InstalledO365Apps", $InstalledO365Apps, "", [System.Management.Automation.ScopedItemOptions]::AllScope)
            11 = [System.Management.Automation.Runspaces.SessionStateVariableEntry]::new("ShowTech", $ShowTech, "", [System.Management.Automation.ScopedItemOptions]::AllScope)
            12 = [System.Management.Automation.Runspaces.SessionStateVariableEntry]::new("ShowRunningConfig", $ShowRunningConfig, "", [System.Management.Automation.ScopedItemOptions]::AllScope)
            13 = [System.Management.Automation.Runspaces.SessionStateVariableEntry]::new("DeviceInfo", $DeviceInfo, "", [System.Management.Automation.ScopedItemOptions]::AllScope)
        }

        # Create runspace pool to include required modules.
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $SessionState.ImportPSModule($(Join-Path -Path $ModulesPath -ChildPath Master_Functions))
        $SessionState.ImportPSModule($(Join-Path -Path $ModulesPath -ChildPath $PsModule))
        If ($ShowTech) {
            $SessionState.ImportPSModule($(Join-Path -Path $ModulesPath -ChildPath Cisco_Functions))
        }
        ForEach ($Key in $GlobalVars.Keys) {
            $SessionState.Variables.Add($GlobalVars.$Key)
        }
        $RunspacePool = [runspacefactory]::CreateRunspacePool(1, 1, $SessionState, $Host)
        $RunspacePool.Open()

        $NewCKLVulnList = New-Object System.Collections.Generic.List[System.Object]
        Foreach ($NewVuln in $NewCKL.CHECKLIST.STIGS.iSTIG.VULN) {
            $NewCKLVulnList.Add($NewVuln.SelectSingleNode('./STIG_DATA[VULN_ATTRIBUTE="Vuln_Num"]/ATTRIBUTE_DATA').InnerText)
        }

        # Process each STIG item
        ForEach ($Vuln in $NewCKL.CHECKLIST.STIGS.iSTIG.VULN) {
            $AnswerApplied = $false
            $RuleID = $Vuln.SelectSingleNode('./STIG_DATA[VULN_ATTRIBUTE="Rule_ID"]/ATTRIBUTE_DATA').InnerText
            $VulnID = $Vuln.SelectSingleNode('./STIG_DATA[VULN_ATTRIBUTE="Vuln_Num"]/ATTRIBUTE_DATA').InnerText

            If ($SelectVuln) {
                $SelectVuln | ForEach-Object {
                    if ($_ -in $NewCKLVulnList) {
                        if ($VulnID -notin $SelectVuln) {
                            Continue
                        }
                    }
                }
            }
            If ($ExcludeVuln) {
                $ExcludeVuln | ForEach-Object {
                    if ($_ -in $NewCKLVulnList) {
                        if ($VulnID -in $ExcludeVuln) {
                            Write-Log $LogPath "Vul ID : $($VulnID)" $LogComponent "Info" -OSPlatform $OSPlatform
                            Write-Log $LogPath "    Excluded due to -ExcludeVuln parameter" $LogComponent "Warning" -OSPlatform $OSPlatform
                            Continue
                        }
                    }
                }
            }

            # If an Evaluate-STIG function exists for STIG item, run it here
            If ($PsModuleCommands | Where-Object Name -EQ "Get-$($VulnID.Replace('-',''))") {
                Write-Progress -Id ($ProgressId + 1) -ParentId $ProgressId -Activity "Checklist: $($CklOutFile)" -Status "Evaluating $($VulnID)" -PercentComplete ($CurrentSubStep / $TotalSubSteps * 100)
                Write-Log $LogPath "Vul ID : $($VulnID)" $LogComponent "Info" -OSPlatform $OSPlatform
                Write-Log $LogPath "    Running $($PsModule)" $LogComponent "Info" -OSPlatform $OSPlatform

                If ($AnswerFile) {
                    $CheckCommand = "Get-$($VulnID.Replace('-','')) -AnswerFile " + [Char]34 + $($AnswerFile) + [Char]34 + " -ScanType $($ScanType) -AnswerKey $($AnswerKey) -Username $($Username) -UserSID $($UserSID)"
                }
                Else {
                    $CheckCommand = "Get-$($VulnID.Replace('-','')) -ScanType $($ScanType) -AnswerKey $($AnswerKey) -Username $($Username) -UserSID $($UserSID)"
                }
                Try {
                    If ($WebOrDB) {
                        If ($PSBoundParameters.Site) {
                            $CheckCommand = $CheckCommand + " -SiteName " + [Char]34 + $PSBoundParameters.Site + [Char]34
                        }
                        ElseIf ($PSBoundParameters.Instance) {
                            #$CheckCommand = $CheckCommand + " -SiteName " + [Char]34 + $PSBoundParameters.Instance + [Char]34
                        }

                        # JJS Add SQL test and add Instance data here -Instance $($Instance) -Database $($Database)
                        if ($TemplateName -like "*SQL*Instance*" -or $TemplateName -like "*SQL*DB*") {
                            $CheckCommand = $CheckCommand + " -Instance '$($Instance)' -Database '$($Database)'"
                        }
                    }

                    $RSCodeText = 'Try {' + $CheckCommand + '} Catch {$Result=@{CodeFail=$true;Message=$($_.Exception.Message);ScriptName=$($Error[0].InvocationInfo.ScriptName);ScriptLineNumber=$($Error[0].InvocationInfo.ScriptLineNumber);Line=$(($Error[0].InvocationInfo.Line).Trim())}; Return $Result}' | Out-String
                    $RSCodeSB = [scriptblock]::Create($RSCodeText)
                    $Result = Invoke-CodeWithTimeout -Code $RSCodeSB -Timeout $VulnTimeout -RunspacePool $RunspacePool

                    If ($Result.CodeFail) {
                        Throw "CodeFail"
                    }
                    ElseIf ($Result.Status -ne "Not_Reviewed") {
                        Write-Log $LogPath "    Scan Module determined Status is '$($Result.Status)'" $LogComponent "Info" -OSPlatform $OSPlatform
                    }
                    Else {
                        Write-Log $LogPath "    Scan Module unable to determine Status" $LogComponent "Info" -OSPlatform $OSPlatform
                    }

                    If ($Result.AFStatus -ne "") {
                        $StatusChange = $false
                        $PreComment = ""
                        If ($Result.AFStatus -ne $Result.Status) {
                            $StatusChange = $true
                            $Vuln.STATUS = [String]$Result.AFStatus
                            $PreComment = "Evaluate-STIG answer file for Key '$($Result.AFKey)' is changing the Status from $($Result.Status) to $($Result.AFStatus) and providing the below comment on $($ScanStartDate):`r`n" | Out-String

                            #Add Metadata for STIGMAN
                            $AnswerFileMod = $NewCKL.CreateElement("Evaluate-STIG")
                            $AnswerFileModfile = $NewCKL.CreateElement("answerfile")
                            $AnswerFileModfile.InnerText = "$(Split-Path $AnswerFile -Leaf)"
                            $AnswerFileModstatus = $NewCKL.CreateElement("afmod")
                            $AnswerFileModstatus.InnerText = "True"
                            $AnswerFileModoldstatus = $NewCKL.CreateElement("oldstatus")
                            $AnswerFileModoldstatus.InnerText = $Result.Status
                            $null = $AnswerFileMod.AppendChild($AnswerFileModfile)
                            $null = $AnswerFileMod.AppendChild($AnswerFileModstatus)
                            $null = $AnswerFileMod.AppendChild($AnswerFileModoldstatus)
                            $null = $Vuln.AppendChild($AnswerFileMod)
                            $AnswerFileComment = $NewCKL.CreateComment($AnswerFileMod.OuterXml)
                            $null = $AnswerFileMod.ParentNode.ReplaceChild($AnswerFileComment, $AnswerFileMod)
                        }
                        Else {
                            $Vuln.STATUS = [String]$Result.Status
                            $PreComment = "Evaluate-STIG answer file for Key '$($Result.AFKey)' is providing the below comment on $($ScanStartDate):`r`n" | Out-String
                        }
                    }
                    Else {
                        $Vuln.STATUS = [String]$Result.Status
                    }
                    # Truncate Finding Details if over 32767 characters
                    If (($Result.FindingDetails | Measure-Object -Character).Characters -gt 32767) {
                        $Result.FindingDetails = $($Result.FindingDetails).Substring(0, [System.Math]::Min(32767, $($Result.FindingDetails).Length)) + "`r`n`r`n---truncated results. met character limit---" | Out-String
                    }
                    $Vuln.FINDING_DETAILS = [String]$Result.FindingDetails

                    If ($Result.Comments -ne "") {
                        $AnswerApplied = $true
                        Write-Log $LogPath "    Adding Comment from answer file for Key '$($Result.AFKey)'" $LogComponent "Info" -OSPlatform $OSPlatform
                        If ($StatusChange -eq $true) {
                            Write-Log $LogPath "    Answer file for Key '$($Result.AFKey)' is changing the Status from '$($Result.Status)' to '$($Result.AFStatus)'" $LogComponent "Warning" -OSPlatform $OSPlatform
                        }
                        $FinalComments = $PreComment + $Result.Comments
                        # Truncate Comment if over 32767 characters
                        If (($FinalComments | Measure-Object -Character).Characters -gt 32767) {
                            $FinalComments = $FinalComments.Substring(0, [System.Math]::Min(32767, $FinalComments.Length)) + "`r`n`r`n---truncated results. met character limit---" | Out-String
                        }
                        If (($Result.FindingDetails).Trim() -eq "") {
                            $Vuln.FINDING_DETAILS = [String]$FinalComments
                        }
                        $Vuln.COMMENTS = [String]$FinalComments
                    }
                    If ($Result.Severity.Length -ne 0) {
                        Switch ($Vuln.SelectSingleNode('./STIG_DATA[VULN_ATTRIBUTE="Severity"]/ATTRIBUTE_DATA').InnerText) {
                            "high" {
                                $CurrentSeverity = "CAT I"
                            }
                            "medium" {
                                $CurrentSeverity = "CAT II"
                            }
                            "low" {
                                $CurrentSeverity = "CAT III"
                            }
                        }
                        Switch ($Result.Severity) {
                            "high" {
                                $NewSeverity = "CAT I"
                            }
                            "medium" {
                                $NewSeverity = "CAT II"
                            }
                            "low" {
                                $NewSeverity = "CAT III"
                            }
                        }
                        Write-Log $LogPath "    Changing Severity from $($CurrentSeverity) to $($NewSeverity) per STIG" $LogComponent "Warning" -OSPlatform $OSPlatform
                        $Vuln.SelectSingleNode('./STIG_DATA[VULN_ATTRIBUTE="Severity"]/ATTRIBUTE_DATA').InnerText = [String]$Result.Severity
                    }
                }
                Catch {
                    Write-Log $LogPath "    Failed to execute scan for RuleID $RuleID" $LogComponent "Error" -OSPlatform $OSPlatform
                    If ($($_.Exception.Message) -eq "Job timed out.") {
                        Write-Host "$ShortName (Get-$($VulnID.Replace('-',''))) : Timeout of $VulnTimeout minutes reached." -ForegroundColor Yellow
                        Write-Log $LogPath "    Check Timeout of $VulnTimeout minutes reached.  Aborting." $LogComponent "Error" -OSPlatform $OSPlatform
                    }
                    ElseIf ($_.Exception.Message -eq "CodeFail") {
                        $CheckFail = $true
                        Write-Host "$ShortName ($($VulnID)) : Failed.  See Evaluate-STIG.log for details." -ForegroundColor Red
                        Write-Log $LogPath "    $($Result.Message)" $LogComponent "Error" -OSPlatform $OSPlatform
                        Write-Log $LogPath "    $($Result.ScriptName)" $LogComponent "Error" -OSPlatform $OSPlatform
                        Write-Log $LogPath "    Line: $($Result.ScriptLineNumber)" $LogComponent "Error" -OSPlatform $OSPlatform
                        Write-Log $LogPath "    $($Result.Line)" $LogComponent "Error" -OSPlatform $OSPlatform
                    }
                    Else {
                        $CheckFail = $true
                        Write-Host "$ShortName ($($VulnID)) : Failed.  See Evaluate-STIG.log for details." -ForegroundColor Red
                        Write-Log $LogPath "    $($_.Exception.Message)" $LogComponent "Error" -OSPlatform $OSPlatform
                        Write-Log $LogPath "    $($_.InvocationInfo.ScriptName)" $LogComponent "Error" -OSPlatform $OSPlatform
                        Write-Log $LogPath "    Line: $($_.InvocationInfo.ScriptLineNumber)" $LogComponent "Error" -OSPlatform $OSPlatform
                        Write-Log $LogPath "    $(($_.InvocationInfo.Line).Trim())" $LogComponent "Error" -OSPlatform $OSPlatform
                    }
                }
            }
            # If not checked by Evaluate-STIG function, look to see if there is an answer in an answer file for this STIG item
            ElseIf ($AnswerFile) {
                $AnswerData = (Get-CorporateComment -AnswerFile $AnswerFile -VulnID $VulnID -AnswerKey $AnswerKey)
                If ($Vuln.STATUS -eq $AnswerData.ExpectedStatus) {
                    $AnswerApplied = $true
                    $StatusChange = $false
                    $PreComment = ""
                    Write-Log $LogPath "Vul ID : $($VulnID)" $LogComponent "Info" -OSPlatform $OSPlatform
                    Write-Log $LogPath "    Adding Comment from answer file for Key '$($AnswerData.AFKey)'" $LogComponent "Info" -OSPlatform $OSPlatform
                    If ($AnswerData.AFStatus -ne $Vuln.STATUS) {
                        $StatusChange = $true
                        $PreComment = "Evaluate-STIG answer file for Key '$($AnswerData.AFKey)' is changing the Status from $($Vuln.STATUS) to $($AnswerData.AFStatus) and providing the below comment on $($ScanStartDate):`r`n" | Out-String

                        #Add Metadata for STIGMAN
                        $AnswerFileMod = $NewCKL.CreateElement("Evaluate-STIG")
                        $AnswerFileModfile = $NewCKL.CreateElement("answerfile")
                        $AnswerFileModfile.InnerText = "$(Split-Path $AnswerFile -Leaf)"
                        $AnswerFileModstatus = $NewCKL.CreateElement("afmod")
                        $AnswerFileModstatus.InnerText = "True"
                        $AnswerFileModoldstatus = $NewCKL.CreateElement("oldstatus")
                        $AnswerFileModoldstatus.InnerText = $Vuln.STATUS
                        $null = $AnswerFileMod.AppendChild($AnswerFileModfile)
                        $null = $AnswerFileMod.AppendChild($AnswerFileModstatus)
                        $null = $AnswerFileMod.AppendChild($AnswerFileModoldstatus)
                        $null = $Vuln.AppendChild($AnswerFileMod)
                        $AnswerFileComment = $NewCKL.CreateComment($AnswerFileMod.OuterXml)
                        $null = $AnswerFileMod.ParentNode.ReplaceChild($AnswerFileComment, $AnswerFileMod)
                    }
                    Else {
                        $PreComment = "Evaluate-STIG answer file for Key '$($AnswerData.AFKey)' is providing the below comment on $($ScanStartDate):`r`n" | Out-String
                    }
                    If ($StatusChange -eq $true) {
                        Write-Log $LogPath "    Answer file for Key '$($AnswerData.AFKey)' is changing the Status from '$($Vuln.STATUS)' to '$($AnswerData.AFStatus)'" $LogComponent "Warning" -OSPlatform $OSPlatform
                    }
                    $FinalComments = $PreComment + $AnswerData.AFComment
                    # Truncate Comment if over 32767 characters
                    If (($FinalComments | Measure-Object -Character).Characters -gt 32767) {
                        $FinalComments = $FinalComments.Substring(0, [System.Math]::Min(32767, $FinalComments.Length)) + "`r`n`r`n---truncated results. met character limit---" | Out-String
                    }
                    If (($Vuln.FINDING_DETAILS).Trim() -eq "") {
                        $Vuln.FINDING_DETAILS = [String]$FinalComments
                    }
                    $Vuln.STATUS = [String]$AnswerData.AFStatus
                    $Vuln.COMMENTS = [String]$FinalComments
                }
            }

            # Check previous .ckl for administrator overrides.  Ignore if an answer file comment has already been applied.
            If ("LEGACY_ID" -in $Vuln.STIG_DATA.VULN_ATTRIBUTE) {
                $LegacyIDs = $Vuln.SelectNodes('./STIG_DATA[VULN_ATTRIBUTE="LEGACY_ID"]/ATTRIBUTE_DATA').InnerText
                $LegacyVulnID = (Select-String -InputObject $LegacyIDS -Pattern "V-\d{4,}" | ForEach-Object { $_.Matches }).Value
            }
            If ($AnswerApplied -ne $true) {
                If (($Vuln.STATUS -eq "Not_Reviewed") -or ($Vuln.STATUS -eq "Open")) {
                    ForEach ($OldVuln in $OldCKL.CHECKLIST.STIGS.iSTIG.VULN) {
                        $OldVulnID = $OldVuln.SelectSingleNode('./STIG_DATA[VULN_ATTRIBUTE="Vuln_Num"]/ATTRIBUTE_DATA').InnerText
                        If (($OldVulnID -eq $VulnID -or $OldVulnID -eq $LegacyVulnID) -and ($OldVuln.COMMENTS.Length -gt 0) -and ($OldVuln.COMMENTS -notlike "*Evaluate-STIG*($($PsModule))*") -and ($OldVuln.COMMENTS -notlike "*Evaluate-STIG*answer file*")) {
                            Switch ($Vuln.STATUS) {
                                "Not_Reviewed" {
                                    If (-Not($PsModuleCommands | Where-Object Name -EQ "Get-$($VulnID.Replace('-',''))")) {
                                        Write-Log $LogPath "Vul ID : $($VulnID)" $LogComponent "Info" -OSPlatform $OSPlatform
                                    }
                                    Write-Log $LogPath "    Adding administrator comment from previous checklist" $LogComponent "Info" -OSPlatform $OSPlatform
                                    # Update Not_Reviewed finding details and comments only from previous checklist.  Leave as Not_Reviewed to promote verification of configuration.
                                    $Vuln.COMMENTS = [String]($OldVuln.COMMENTS).Trim()
                                }
                                "Open" {
                                    If (-Not($PsModuleCommands | Where-Object Name -EQ "Get-$($VulnID.Replace('-',''))")) {
                                        Write-Log $LogPath "Vul ID : $($VulnID)" $LogComponent "Info" -OSPlatform $OSPlatform
                                    }
                                    Write-Log $LogPath "    Adding administrator comment from previous checklist" $LogComponent "Info" -OSPlatform $OSPlatform
                                    # Update comments only from previous checklist.  Opens are to be left open if detected from scans.
                                    $Vuln.COMMENTS = [String]($OldVuln.COMMENTS).Trim()
                                }
                            }
                        }
                    }
                }
            }
            $CurrentSubStep++
        }
        $RunspacePool.Close()
        $RunspacePool.Dispose()
        Write-Progress -Id ($ProgressId + 1) -ParentId $ProgressId -Activity "Checklist: $($CklOutFile)" -Completed

        Write-Log $LogPath "Saving $($ResultFile.FullName)" $LogComponent "Info" -OSPlatform $OSPlatform
        if ($Marking) {
            $MarkingFooter = $NewCKL.CreateComment("                                                                                          $Marking                                                                                          ")
            $null = $NewCKL.InsertAfter($MarkingFooter, $NewCKL.CHECKLIST)
        }
        $NewCKL.Save($ResultFile.FullName)

        #Validate Checklist

        Write-Log $STIGLog "Validating CKL File..." $LogComponent "Info" -OSPlatform $OSPlatform
        $CKLValid = Test-XmlValidation -XmlFile $ResultFile.FullName -SchemaFile $Checklist_xsd

        If ($CKLValid -eq $true) {
            Write-Log $LogPath "'$CklOutFile' : Passed." $LogComponent "Info" -OSPlatform $OSPlatform
            # Move old checklists to Previous subfolder
            ForEach ($File in $OldCKLFileList) {
                If ($NoPrevious) {
                    Write-Log $LogPath "Removing previous checklist $($File.Name)" $LogComponent "Info" -OSPlatform $OSPlatform
                    Remove-Item -Path $File.FullName -Force
                }
                Else {
                    $PreviousFolder = Get-Date -Format yyyy-MM-dd
                    If (-Not(Test-Path -Path (Join-Path -Path $CklDestinationPath -ChildPath "Previous" | Join-Path -ChildPath $PreviousFolder))) {
                        New-Item -Path $CklDestinationPath -Name (Join-Path -Path "Previous" -ChildPath $PreviousFolder) -ItemType Directory | Out-Null
                    }
                    Write-Log $LogPath "Moving previous checklist $($File.Name) to $CklDestinationPath\Previous\$PreviousFolder\" $LogComponent "Info" -OSPlatform $OSPlatform
                    Move-Item -Path $File.FullName -Destination (Join-Path -Path $CklDestinationPath -ChildPath "Previous" | Join-Path -ChildPath $PreviousFolder) -Force
                }
            }

            Write-Log $LogPath "Copying new checklist $($ResultFile.Name) to $CklDestinationPath" $LogComponent "Info" -OSPlatform $OSPlatform
            Copy-Item -Path $ResultFile.FullName -Destination "$CklDestinationPath" -Force
        }
        Else {
            $BadCklDestination = Join-Path -Path $WorkingDir -ChildPath "Bad_CKL"
            Write-Log $LogPath "'$CklOutFile' : failed.  Moving to $BadCklDestination." $LogComponent "Error" -OSPlatform $OSPlatform
            ForEach ($Item in $CKLValid.Message) {
                Write-Log $LogPath $Item $LogComponent "Error" -OSPlatform $OSPlatform
            }
            Write-Host "'$CklOutFile' : failed schema validation.  Moving to $BadCklDestination." -ForegroundColor Red
            If (-Not(Test-Path $BadCklDestination)) {
                New-Item -Path $BadCklDestination -ItemType Directory | Out-Null
            }
            Move-Item -Path $ResultFile.FullName -Destination $BadCklDestination -Force
        }

        If ($CheckFail -eq $true) {
            Return "ErrorDetected"
        }
        Else {
            Return "Success"
        }
    }
}

Function Get-CklData {
    <#
    .Synopsis
        List key fields from a STIG checklist file (.ckl)
    .DESCRIPTION
        Enumerates a given .ckl file into a PowerShell array object with the following fields:
            - STIG Name
            - Checklist File Name
            - HostName
            - Vuln ID
            - Rule ID
            - Rule Title
            - Status
            - Severity
            - Documentable
            - Check Content
            - Finding Details
            - Comments
    .EXAMPLE
        Get-CklData -CklFile C:\Checklists\Windows10.ckl

        Lists all checks in the checklist.
    .EXAMPLE
        Get-CklData -CklFile C:\Checklists\Windows10.ckl | Where Status -eq "Open"

        Lists just Open checks in the checklist.
    .INPUTS
        -CklFile
            Required.  Path to .ckl file.
    .OUTPUTS
        Outputs to an array object.
    .LINK
        https://spork.navsea.navy.mil/nswc-crane-division/evaluate-stig
    .NOTES
        Dan Ireland - daniel.ireland@navy.mil
    #>

    Param (
        [Parameter(Mandatory = $true)]
        [String]$CklFile
    )

    Try {
        $FileInfo = Get-Item $CklFile -ErrorAction Stop
        If ($FileInfo.Extension -ne ".ckl") {
            Throw "'$($CklFile)' is not a .ckl file type."
        }

        $CklContent = (Select-Xml -XPath / -Path $CklFile -ErrorAction Stop).Node   # Read file into an XmlDocument object
        $STIG = $CklContent.CHECKLIST.stigs.iSTIG.STIG_INFO.SelectSingleNode('./SI_DATA[SID_NAME="stigid"]/SID_DATA').InnerText   # Extract the STIG ID from the .ckl
        $HostName = $CklContent.CHECKLIST.ASSET.HOST_NAME
        $Output = New-Object System.Collections.ArrayList
        ForEach ($Vuln in $CklContent.CHECKLIST.STIGS.iSTIG.VULN) {
            Switch ($Vuln.SelectSingleNode('./STIG_DATA[VULN_ATTRIBUTE="Severity"]/ATTRIBUTE_DATA').InnerText) {
                # Convert the Severity into a CAT level
                "high" {
                    $Severity = "CAT_I"
                }
                "medium" {
                    $Severity = "CAT_II"
                }
                "low" {
                    $Severity = "CAT_III"
                }
                Default {
                    $Severity = $_
                }
            }

            $NewObj = [PSCustomObject]@{
                STIG           = $STIG
                Checklist      = $FileInfo.Name
                HostName       = $HostName
                VulnID         = ($Vuln.SelectSingleNode('./STIG_DATA[VULN_ATTRIBUTE="Vuln_Num"]/ATTRIBUTE_DATA').InnerText)   # Extract the Vuln ID of the STIG item
                RuleID         = ($Vuln.SelectSingleNode('./STIG_DATA[VULN_ATTRIBUTE="Rule_ID"]/ATTRIBUTE_DATA').InnerText)   # Extract the Rule ID of the STIG item
                RuleTitle      = ($Vuln.SelectSingleNode('./STIG_DATA[VULN_ATTRIBUTE="Rule_Title"]/ATTRIBUTE_DATA').InnerText) -replace "&#xA;", ""   # Extract the Rule Title of the STIG item
                Status         = $Vuln.Status
                Severity       = $Severity
                Documentable   = ($Vuln.SelectSingleNode('./STIG_DATA[VULN_ATTRIBUTE="Documentable"]/ATTRIBUTE_DATA').InnerText)   # Extract the Documentable of the STIG item
                CheckContent   = ($Vuln.SelectSingleNode('./STIG_DATA[VULN_ATTRIBUTE="Check_Content"]/ATTRIBUTE_DATA').InnerText)   # Extract the Check Content of the STIG item
                FindingDetails = $Vuln.FINDING_DETAILS
                Comments       = $Vuln.COMMENTS
            }
            $Output.Add($NewObj) | Out-Null
        }
        Return $Output
    }
    Catch {
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
}

function Repair-XmlString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$string
    )

    $pattern = "(?<=\&).+?(?=\;)"
    $hex = "$([regex]::matches($string, $pattern).value)"
    if ($hex){
        $hex -split " " | Foreach-Object {
            $string = $string -replace "&$_;", [char[]]$([BYTE][CHAR]([CONVERT]::toint16($($_ -replace "#","0"),16)))
        }
    }

    Return ($string -Replace "`0", "[null]")
}

Function Send-CheckResult {
    # Returns custom check data to Write-Ckl for inclusion into the checklist file
    Param (
        # Scan Module Name
        [Parameter(Mandatory = $true)]
        [String]$Module,

        # Status of check
        [Parameter(Mandatory = $true)]
        [String]$Status,

        # Finding Details of check
        [Parameter(Mandatory = $false)]
        [String]$FindingDetails,

        # Answer File Source Key
        [Parameter(Mandatory = $false)]
        [String]$AFKey,

        # Answer File FinalStatus
        [Parameter(Mandatory = $false)]
        [String]$AFStatus,

        # Approved Comments of check
        [Parameter(Mandatory = $false)]
        [String]$Comments,

        # Severity Change
        [Parameter(Mandatory = $false)]
        [String]$Severity
    )

    [hashtable]$CheckResults = @{ }
    $CheckResults.Status = "Not_Reviewed" #acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $CheckResults.FindingDetails = ""
    $CheckResults.AFKey = ""
    $CheckResults.AFStatus = ""
    $CheckResults.Comments = ""

    $FindingDetailsText = ""

    Switch ($Status) {
        "Open" {
            $CheckResults.Status = "Open"
            $FindingDetailsText += "Evaluate-STIG $($ESVersion) ($($Module)) found this to be OPEN on $($ScanStartDate):" | Out-String
            $FindingDetailsText += "---------------------------------------------------------------" | Out-String
        }
        "NotAFinding" {
            $CheckResults.Status = "NotAFinding"
            $FindingDetailsText += "Evaluate-STIG $($ESVersion) ($($Module)) found this to be NOT A FINDING on $($ScanStartDate):" | Out-String
            $FindingDetailsText += "------------------------------------------------------------------------" | Out-String
        }
        "Not_Applicable" {
            $CheckResults.Status = "Not_Applicable"
            $FindingDetailsText += "Evaluate-STIG $($ESVersion) ($($Module)) found this to be NOT APPLICABLE on $($ScanStartDate):" | Out-String
            $FindingDetailsText += "-------------------------------------------------------------" | Out-String
        }
    }

    If ($FindingDetails) {
        $FindingDetailsText += Repair-XmlString -String $FindingDetails
    }
    $CheckResults.FindingDetails = $FindingDetailsText

    If ($AFKey) {
        $CheckResults.AFKey = Repair-XmlString -String $AFKey
    }

    If ($AFStatus) {
        $CheckResults.AFStatus = Repair-XmlString -String $AFStatus
    }

    If ($Comments) {
        $CheckResults.Comments = Repair-XmlString -String $Comments
    }

    Switch ($Severity) {
        "CAT_I" {
            $CheckResults.Severity = "high"
        }
        "CAT_II" {
            $CheckResults.Severity = "medium"
        }
        "CAT_III" {
            $CheckResults.Severity = "low"
        }
    }

    Return $CheckResults
}

Function Write-Log {
    <#
    .Synopsis
        Write to a CMTrace friendly .log file.
    .DESCRIPTION
        Takes the input and generates an entry for a CMTrace friendly .log file
        by utilizing a PSCustomObject and Generic List to hold the data.
        A string is created and added to the .log file.
    .EXAMPLE
       PS C:\> Write-Log -Path 'C:\Temp\sample.log' -Message 'Test Message' -Component 'Write-Log' -MessageType Verbose -OSPlatform Windows
    .INPUTS
        -Path
            Use of this parameter is required. Forced to be a String type. The path to where the .log file is located.
        -Message
            Use of this parameter is required. Forced to be a String type. The message to pass to the .log file.
        -Component
            Use of this parameter is required. Forced to be a String type. What is providing the Message.
            Typically this is the script or function name.
        -Type
            Use of this parameter is required. Forced to be a String type. What type of output to be. Choices are
            Info, Warning, Error and Verbose.
        -OSPlatform
            Use of this parameter is required. Forced to be a String type. What OS platform the system is. Choices are Windows or Linux.
    .OUTPUTS
        No output. Writes an entry to a .log file via Add-Content.
    .NOTES
        Resources/Credits:
            Dan Ireland - daniel.ireland@navy.mil
            Brent Betts - brent.betts@navy.mil
        Helpful URLs:
            Russ Slaten's Blog Post - Logging in CMTrace format from PowerShell
            https://blogs.msdn.microsoft.com/rslaten/2014/07/28/logging-in-cmtrace-format-from-powershell/
    #>

    Param (
        [Parameter(Mandatory = $true)]
        [String]$Path,

        [Parameter(Mandatory = $true)]
        [String]$Message,

        [Parameter(Mandatory = $true)]
        [String]$Component,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Info", "Warning", "Error", "Verbose")]
        [String]$Type,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Windows", "Linux")]
        [String]$OSPlatform
    )

    Switch ($Type) {
        'Info' {
            [Int]$Type = 1
        }
        'Warning' {
            [Int]$Type = 2
        }
        'Error' {
            [Int]$Type = 3
        }
        'Verbose' {
            [Int]$Type = 4
        }
    }

    # Obtain date/time
    Switch ($OSPlatform) {
        "Windows" {
            $DateTime = New-Object -ComObject WbemScripting.SWbemDateTime
            $DateTime.SetVarDate($(Get-Date))
            $UtcValue = $DateTime.Value
            $UtcOffset = [Math]::Abs($UtcValue.Substring(21, $UtcValue.Length - 21))
            $user_name = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        }
        "Linux" {
            $UtcOffset = (date +%z_).Trim("-")
            $user_name = whoami
        }
    }

    # Create Object to hold items to log
    $LogItems = New-Object System.Collections.Generic.List[System.Object]
    $NewObj = [PSCustomObject]@{
        Message   = $Message
        Time      = [Char]34 + (Get-Date -Format "HH:mm:ss.fff") + "+$UtcOffset" + [Char]34
        Date      = [Char]34 + (Get-Date -Format "MM-dd-yyyy") + [Char]34
        Component = [Char]34 + $Component + [Char]34
        Context   = [Char]34 + $user_name + [Char]34
        Type      = [Char]34 + $Type + [Char]34
        Thread    = [Char]34 + [Threading.Thread]::CurrentThread.ManagedThreadId + [Char]34
        File      = [Char]34 + [Char]34
    }
    $LogItems.Add($NewObj)

    # Format Log Entry
    $Entry = "<![LOG[$($LogItems.Message)]LOG]!><time=$($LogItems.Time) date=$($LogItems.Date) component=$($LogItems.Component) context=$($LogItems.Context) type=$($LogItems.Type) thread=$($logItems.Thread) file=$($LogItems.File)>"

    # Add to Log
    Add-Content -Path $Path -Value $Entry -ErrorAction SilentlyContinue | Out-Null
}

Function Search-AD {
    Param (
        [String[]]$Filter,
        [String[]]$Properties,
        [String]$SearchRoot
    )

    If ($SearchRoot) {
        $Root = [ADSI]$SearchRoot
    }
    Else {
        $Root = [ADSI]''
    }

    If ($Filter) {
        $LDAP = "(&({0}))" -f ($Filter -join ')(')
    }
    Else {
        $LDAP = "(name=*)"
    }

    If (-Not($Properties)) {
        $Properties = 'Name', 'ADSPath'
    }

    (New-Object ADSISearcher -ArgumentList @($Root, $LDAP, $Properties) -Property @{PageSize = 1000 }).FindAll() | ForEach-Object {
        $ObjectProps = @{ }
        $_.Properties.GetEnumerator() | ForEach-Object {
            $ObjectProps.Add($_.Name, (-join $_.Value))
        }
        New-Object PSObject -Property $ObjectProps | Select-Object $Properties
    }
}

Function Invoke-TaskAsSYSTEM {
    # Creates a self-deleting scheduled task that will run as the SYSTEM account and executes it.
    Param (
        [Parameter(Mandatory = $true)]
        [String]$TaskName,

        [Parameter(Mandatory = $true)]
        [String]$FilePath,

        [Parameter(Mandatory = $false)]
        [String]$ArgumentList,

        [Parameter(Mandatory = $false)]
        [Int]$MaxRunInMinutes
    )

    $TaskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date)
    $TaskAction = New-ScheduledTaskAction -Execute $FilePath -Argument $ArgumentList
    $TaskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes $MaxRunInMinutes) -AllowStartIfOnBatteries
    $TaskObj = Register-ScheduledTask -TaskName $TaskName -Trigger $TaskTrigger -Action $TaskAction -Settings $TaskSettings -User "SYSTEM" -Force

    $RegisteredTask = Get-ScheduledTask -TaskName $TaskName
    $RegisteredTask.Triggers[0].EndBoundary = ((Get-Date).AddMinutes($MaxRunInMinutes)).ToString('s')
    $RegisteredTask.Settings.DeleteExpiredTaskAfter = 'PT0S'
    $RegisteredTask | Set-ScheduledTask

    Start-ScheduledTask -InputObject $TaskObj
    While ((Get-ScheduledTask -TaskName $TaskName).State -eq "Running") {
        Start-Sleep -Seconds 1
    }
    $TaskResult = Get-ScheduledTaskInfo -InputObject $TaskObj
    Unregister-ScheduledTask -InputObject $TaskObj -Confirm:$false
    Return $TaskResult
}

Function Get-RegistryResult {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Path,

        [Parameter(Mandatory = $false)]
        [String]$ValueName
    )

    $Value = $null
    $Type = $null
    If ($ValueName -eq "(default)") {
        $ValueNameToCheck = ""
    }
    ElseIf (-Not($ValueName)) {
        $ValueName = "(default)"
        $ValueNameToCheck = ""
    }
    Else {
        $ValueNameToCheck = $ValueName
    }

    $Output = New-Object System.Collections.Generic.List[System.Object]
    If (Test-Path $Path) {
        If (Get-ItemProperty -Path $Path -Name $ValueNameToCheck -ErrorAction SilentlyContinue) {
            $RegistryKey = Get-Item -Path $Path -ErrorAction SilentlyContinue
            If (-Not($null -eq $RegistryKey.GetValue($ValueNameToCheck))) {
                $Value = Get-ItemPropertyValue -Path $Path -Name $ValueNameToCheck
                $ValueType = $RegistryKey.GetValueKind($ValueNameToCheck)
                Switch ($ValueType) {
                    "Binary" {
                        $Type = "REG_BINARY"
                    }
                    "Dword" {
                        $Type = "REG_DWORD"
                    }
                    "ExpandString" {
                        $Type = "REG_EXPAND_SZ"
                        $Value = $Value.Trim()
                    }
                    "MultiString" {
                        $Type = "REG_MULTI_SZ"
                        If (-Not([String]::IsNullOrEmpty($Value))) {
                            $Value = $Value.Trim()
                        }
                    }
                    "Qword" {
                        $Type = "REG_QWORD"
                    }
                    "String" {
                        $Type = "REG_SZ"
                        $Value = $Value.Trim()
                    }
                }
            }
        }

        If (-Not($Value) -and $ValueName -eq "(default)") {
            $Value = "(value not set)"
            $Type = "REG_SZ"
        }
        ElseIf (-Not($Type)) {
            $ValueName = "(NotFound)"
            $Value = "(NotFound)"
            $Type = "(NotFound)"
        }
        ElseIf (($Type -in @("REG_EXPAND_SZ", "REG_MULTI_SZ", "REG_SZ")) -and ([String]::IsNullOrEmpty($Value))) {
            $Value = "(blank)"
        }

    }
    Else {
        $Path = "(NotFound)"
        $ValueName = "(NotFound)"
        $Value = "(NotFound)"
        $Type = "(NotFound)"
    }

    $NewObj = [PSCustomObject]@{
        Key       = ($Path)
        ValueName = ($ValueName)
        Value     = ($Value)
        Type      = ($Type)
    }
    $Output.Add($NewObj)

    Return $Output
}

Function Get-InstalledSoftware {
    $SoftwareList = New-Object System.Collections.Generic.List[System.Object]
    $OSArch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
    Switch ($OSArch) {
        "64-Bit" {
            $RegPath = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
        }
        Default {
            $RegPath = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        }
    }
    ForEach ($Path in $RegPath) {
        $RegKeys += (Get-ChildItem -Path $Path -ErrorAction SilentlyContinue).Name.Replace("HKEY_LOCAL_MACHINE", "HKLM:")
    }

    ForEach ($Key in $RegKeys) {
        Try {
            $Properties = Get-ItemProperty -Path $Key -ErrorAction SilentlyContinue # A corrupt registry value will cause this to fail.  If so then we do this a different, though slower way, below.

            If ($Properties.DisplayName) {
                $DisplayName = ($Properties.DisplayName).Trim()
            }
            Else {
                $DisplayName = ""
            }

            If ($Properties.DisplayVersion) {
                $DisplayVersion = ($Properties.DisplayVersion -replace "[^a-zA-Z0-9.-_()]").Trim()
            }
            Else {
                $DisplayVersion = ""
            }

            If ($Properties.Publisher) {
                $Publisher = ($Properties.Publisher).Trim()
            }
            Else {
                $Publisher = ""
            }

            If ($Properties.InstallLocation) {
                $InstallLocation = ($Properties.InstallLocation).Trim()
            }
            Else {
                $InstallLocation = ""
            }

            If ($Properties.SystemComponent) {
                $SystemComponent = $Properties.SystemComponent
            }
            Else {
                $SystemComponent = ""
            }

            If ($Properties.ParentKeyName) {
                $ParentKeyName = $Properties.ParentKeyName
            }
            Else {
                $ParentKeyName = ""
            }
        }
        Catch {
            # If above method fails, then do this
            Try {
                $DisplayName = (Get-ItemPropertyValue $Key -Name DisplayName).Trim()
            }
            Catch {
                $DisplayName = ""
            }

            Try {
                $DisplayVersion = (Get-ItemPropertyValue $Key -Name DisplayVersion).Replace("[^a-zA-Z0-9.-_()]", "").Trim()
            }
            Catch {
                $DisplayVersion = ""
            }

            Try {
                $Publisher = (Get-ItemPropertyValue $Key -Name Publisher).Trim()
            }
            Catch {
                $Publisher = ""
            }

            Try {
                $InstallLocation = (Get-ItemPropertyValue $Key -Name InstallLocation).Trim()
            }
            Catch {
                $InstallLocation = ""
            }

            Try {
                $SystemComponent = (Get-ItemPropertyValue $Key -Name SystemComponent).Trim()
            }
            Catch {
                $SystemComponent = ""
            }

            Try {
                $ParentKeyName = (Get-ItemPropertyValue $Key -Name ParentKeyName).Trim()
            }
            Catch {
                $ParentKeyName = ""
            }
        }

        If ($DisplayName -and $SystemComponent -ne 1 -and (-Not($ParentKeyName))) {
            $NewObj = [PSCustomObject]@{
                DisplayName     = $DisplayName
                DisplayVersion  = $DisplayVersion
                Publisher       = $Publisher
                InstallLocation = $InstallLocation
            }
            $SoftwareList.Add($NewObj)
        }
    }

    Return $SoftwareList | Select-Object * -Unique | Sort-Object DisplayName
}

Function Get-InstalledO365Apps {
    $RegPaths = @("HKLM:\SOFTWARE\Microsoft\Office\16.0", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\16.0")
    $PossibleApps = @("Access", "Excel", "Groove", "Lync", "OneNote", "Outlook", "PowerPoint", "Project", "Publisher", "Visio", "Word")
    $InstalledApps = New-Object System.Collections.Generic.List[System.Object]

    ForEach ($App in $PossibleApps) {
        ForEach ($Path in $RegPaths) {
            If (Test-Path "$($Path)\$($App)\InstallRoot") {
                $InstallRoot = (Get-ItemProperty "$($Path)\$($App)\InstallRoot").Path
                Switch ($App) {
                    "Access" {
                        $Exe = "msaccess.exe"
                    }
                    "Excel" {
                        $Exe = "excel.exe"
                    }
                    "Lync" {
                        $Exe = "lync.exe"
                    }
                    "OneNote" {
                        $Exe = "onenote.exe"
                    }
                    "Outlook" {
                        $Exe = "outlook.exe"
                    }
                    "PowerPoint" {
                        $Exe = "powerpnt.exe"
                    }
                    "Project" {
                        $Exe = "winproj.exe"
                    }
                    "Publisher" {
                        $Exe = "mspub.exe"
                    }
                    "Visio" {
                        $Exe = "visio.exe"
                    }
                    "Word" {
                        $Exe = "winword.exe"
                    }
                }
                $NewObj = [PSCustomObject]@{
                    Name = $App
                    Exe  = $Exe
                    Path = $InstallRoot
                }
                $InstalledApps.Add($NewObj)
            }
        }
    }
    Return $InstalledApps
}

Function Get-AdobeReaderProInstalls {
    $InstalledVersions = New-Object System.Collections.Generic.List[System.Object]

    $64bitAcrobatDC = @(Get-InstalledSoftware | Where-Object DisplayName -Like "Adobe Acrobat*(64-bit)*")
    If (($64bitAcrobatDC | Measure-Object).Count -ge 1) {
        # 64-bit Adobe Acrobat DC
        $Path = "HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC"
        If (Test-Path (Join-Path -Path $((Get-ItemProperty "$($Path)\InstallPath").'(Default)') -ChildPath "Acrobat.exe") -ErrorAction SilentlyContinue) {
            # 64-bit Adobe Pro and Reader are a unified application and SCAPackageLevel identifies which product is intalled.
            # https://helpx.adobe.com/acrobat/kb/about-acrobat-reader-dc-migration-to-64-bit.html
            $SCAPackageLevel = [Int]((Get-ItemProperty "$($Path)\Installer" -ErrorAction SilentlyContinue)).SCAPackageLevel
            Switch ($SCAPackageLevel) {
                { $_ -gt 1 } {
                    $NewObj = [PSCustomObject]@{
                        Name           = "Adobe Acrobat DC"
                        Version        = "DC"
                        Track          = "Continuous"
                        DisplayVersion = $64bitAcrobatDC[0].DisplayVersion
                        Architecture   = "x64"
                    }
                    If ($NewObj.Name -notin $InstalledVersions.Name) {
                        $InstalledVersions.Add($NewObj)
                    }
                }
                { $_ -eq 1 } {
                    $NewObj = [PSCustomObject]@{
                        Name           = "Adobe Reader DC"
                        Version        = "DC"
                        Track          = "Continuous"
                        DisplayVersion = $64bitAcrobatDC[0].DisplayVersion
                        Architecture   = "x64"
                    }
                    If ($NewObj.Name -notin $InstalledVersions.Name) {
                        $InstalledVersions.Add($NewObj)
                    }
                }
            }
        }
    }

    # 32-bit Adobe Acrobat and Adobe Reader
    $Paths = @("HKLM:\SOFTWARE\WOW6432Node\Adobe\Adobe Acrobat", "HKLM:\SOFTWARE\WOW6432Node\Adobe\Acrobat Reader")
    ForEach ($Path in $Paths) {
        If (Test-Path $Path) {
            Switch (Split-Path $Path -Leaf) {
                "Adobe Acrobat" {
                    $InstallPaths = @((Get-ChildItem $Path -Recurse | Where-Object { $_.Name -like "*InstallPath" -and $null -ne $_.GetValue("") }).Name)
                    ForEach ($Object in ($InstallPaths | Where-Object { $null -ne $_ })) {
                        If (Test-Path (Join-Path -Path $((Get-ItemProperty $($Object.Replace("HKEY_LOCAL_MACHINE", "HKLM:"))).'(Default)') -ChildPath "Acrobat.exe") -ErrorAction SilentlyContinue) {
                            Switch (Split-Path ($Object -Split "Installer")[0] -Leaf) {
                                "11.0" {
                                    $NewObj = [PSCustomObject]@{
                                        Name           = "Adobe Acrobat XI"
                                        Version        = "XI"
                                        Track          = ""
                                        DisplayVersion = (Get-InstalledSoftware | Where-Object { ($_.DisplayName -Like "Adobe Acrobat XI*") }).DisplayVersion
                                        Architecture   = "x86"
                                    }
                                }
                                { ($_ -in @("2015", "2017", "2020")) } {
                                    $NewObj = [PSCustomObject]@{
                                        Name           = "Adobe Acrobat $_"
                                        Version        = $_
                                        Track          = "Classic"
                                        DisplayVersion = (Get-InstalledSoftware | Where-Object { ($_.DisplayName -Like "Adobe Acrobat DC*" -and $_.DisplayVersion -match "15.") -or ($_.DisplayName -Like "Adobe Acrobat 2017*" -and $_.DisplayVersion -match "17.") -or ($_.DisplayName -Like "Adobe Acrobat 2020*" -and $_.DisplayVersion -match "20.") }).DisplayVersion
                                        Architecture   = "x86"
                                    }
                                }
                                "DC" {
                                    $NewObj = [PSCustomObject]@{
                                        Name           = "Adobe Acrobat $_"
                                        Version        = $_
                                        Track          = "Continuous"
                                        DisplayVersion = (Get-InstalledSoftware | Where-Object { ($_.DisplayName -Like "Adobe Acrobat DC*" -and $_.DisplayVersion -gt 20) }).DisplayVersion
                                        Architecture   = "x86"
                                    }
                                }
                            }
                        }
                        If ($NewObj.Name -notin $InstalledVersions.Name) {
                            $InstalledVersions.Add($NewObj)
                        }
                    }
                }
                "Acrobat Reader" {
                    $InstallPaths = @((Get-ChildItem $Path -Recurse | Where-Object { $_.Name -like "*InstallPath" -and $null -ne $_.GetValue("") }).Name)
                    ForEach ($Object in ($InstallPaths | Where-Object { $null -ne $_ })) {
                        If (Test-Path (Join-Path -Path $((Get-ItemProperty $($Object.Replace("HKEY_LOCAL_MACHINE", "HKLM:"))).'(Default)') -ChildPath "AcroRd32.exe") -ErrorAction SilentlyContinue) {
                            Switch (Split-Path ($Object -Split "InstallPath")[0] -Leaf) {
                                "11.0" {
                                    $NewObj = [PSCustomObject]@{
                                        Name           = "Adobe Reader XI"
                                        Version        = "XI"
                                        Track          = ""
                                        DisplayVersion = (Get-InstalledSoftware | Where-Object { ($_.DisplayName -Like "Adobe Reader XI*") }).DisplayVersion
                                        Architecture   = "x86"
                                    }
                                }
                                { ($_ -in @("2015", "2017", "2020")) } {
                                    $NewObj = [PSCustomObject]@{
                                        Name           = "Adobe Reader $_"
                                        Version        = $_
                                        Track          = "Classic"
                                        DisplayVersion = (Get-InstalledSoftware | Where-Object { ($_.DisplayName -Like "Adobe Acrobat Reader DC*" -and $_.DisplayVersion -match "15.") -or ($_.DisplayName -Like "Adobe Acrobat Reader 2017*" -and $_.DisplayVersion -match "17.") -or ($_.DisplayName -Like "Adobe Acrobat Reader 2020*" -and $_.DisplayVersion -match "20.") }).DisplayVersion
                                        Architecture   = "x86"
                                    }
                                }
                                "DC" {
                                    $NewObj = [PSCustomObject]@{
                                        Name           = "Adobe Reader $_"
                                        Version        = $_
                                        Track          = "Continuous"
                                        DisplayVersion = (Get-InstalledSoftware | Where-Object { ($_.DisplayName -Like "Adobe Acrobat Reader*" -and $_.DisplayVersion -gt 20) }).DisplayVersion
                                        Architecture   = "x86"
                                    }
                                }
                            }
                            If ($NewObj.Name -notin $InstalledVersions.Name) {
                                $InstalledVersions.Add($NewObj)
                            }
                        }
                    }
                }
            }
        }
    }

    If ($InstalledVersions) {
        Return $InstalledVersions | Sort-Object Version -Descending
    }
}

Function Confirm-DefaultAcl {
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("FileSystem", "Registry")]
        [String]$Type,

        [Parameter(Mandatory = $true)]
        [String]$Path,

        [Parameter(Mandatory = $true)]
        [Array]$DefaultAcl
    )

    $IsDefault = $true
    $AclFindings = @()
    [hashtable]$AclResults = @{}

    Switch ($Type) {
        "FileSystem" {
            $AclList = icacls $Path
            $AclList = $AclList.Replace($Path, "").Trim() | Select-Object -Index (0..$(($AclList | Measure-Object).Count - 3))
            $AclEnum = @()
            ForEach ($Acl in $AclList) {
                $Rights = ""
                $Identity = $Acl.Split(":")[0]
                $Flags = $Acl.Split(":")[1].Trim()
                ForEach ($Flag in $Flags.Split(")").Replace("(", "")) {
                    If ($Flag -ne "") {
                        $Rights += "("
                        If ($Flag -match ",") {
                            $Multiflags = $Flag.Split(",")
                            $Rights += ($Multiflags | Where-Object { $_ -ne "S" }) -join "," # Ignore the Synchronize (S) flag which can be part of the ACL - especially when configured via group policy
                        }
                        Else {
                            $Rights += $Flag
                        }
                        $Rights += ")"
                    }
                }
                $AclEnum += "$($Identity):$($Rights)"
            }

            # Check default permissions exist
            ForEach ($Acl in $DefaultAcl) {
                If ($Acl -notin $AclEnum) {
                    $IsDefault = $false
                    $AclFindings += $Acl + " - Missing Default Rule"
                }
            }

            # Check for non-default permissions
            ForEach ($Acl in $AclEnum) {
                If ($Acl -notin $DefaultAcl) {
                    $IsDefault = $false
                    $AclFindings += $Acl + " - Non-Default Rule"
                }
            }
        }
        "Registry" {
            #Default ACL is to always be written as if only 1 ACL per acct exist
            <#
	        Translation of permissions:
		        Applies to 						                | Inheritance Flags 	| Propagation Flags
		        ------------------------------------------------------------------------------
		        "This key (folder) only" 						| "None" 				| "None"
		        "This key (folder) and subkeys (subfolders)" 	| "ContainerInherit"	| "None"
		        "Subkeys (subfolders) only"						| "ContainerInherit"	| "InheritOnly"

	        Translation of properties:
		        STIG / GUI Option Name	| PowerShell Option Name
		        --------------------------------------------------------------
		        Principal			| IdentityReference
		        Type 				| AccessControlType
		        Access 				| RegistryRights
		        Read Access			| ReadKey

	        RegistryRights can hold multiple values and sometimes create multiple entries for the same ACL when querying.
	        Specifically, the RegistryRights can be returned as a human readable string (ReadOnly, FullControl) or as a Two's Complement number.
	        The Two's compliment aligns with the permissions described in the "Access Mask Format" in Windows Documentation
	        (https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask-format)

	        Permission Values of Interest:
		        Two's Complement	| Human Readable Equivalent
		        -----------------------------------------------------------
			        -2147483648		| 	Read (Called "ReadKey" for registry keys)
			        -1610612736		| 	Read + Execute
			        1073741824		| 	Write
			        268435456		| 	FullControl





	        DEFINITION OF A 'SPLIT ACL'
		        A split ACL can sometimes occur when a permission has been applied to "this key (folder) and subkeys (subfolders)".
		        The Get-ACL cmdlet will sometimes return a single ACL, as expected with inheritanceFlags = ContainerInherit and propagationFlags = None,
		        but other times will return two ACLs. One ACL will have inheritanceFlags = ContainerInherit and propagationFlags = InheritOnly;
		        the other ACL will have inheritanceFlags = None and propagationFlags = None), which when combined apply the expected permissions.
	        #>

            $Key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(($Path.Replace("HKLM:\", "")), "Default", "ReadPermissions")
            $CurrentAcl = $Key.GetAccessControl() | Select-Object -ExpandProperty Access | Sort-Object IdentityReference

            $CurrentRightsType = ($CurrentAcl | Get-Member * | Where-Object Name -Like "*Rights").Name
            $DefaultRightsType = ($DefaultAcl | Get-Member * | Where-Object Name -Like "*Rights").Name

            #-------------------------
            #Access Rights Translation
            #-------------------------
            $TranslatedACL = New-Object System.Collections.Generic.List[System.Object]
            ForEach ($Obj in $CurrentAcl) {
                #Translate all Two's Compliment Rights into human readable rights
                If ($Obj.$CurrentRightsType -Match "^-?\d+$") {
                    #If the RightsType is a number
                    Switch ($Obj.$CurrentRightsType) {
                        -2147483648 {
                            If ($CurrentRightsType -eq "RegistryRights") {
                                $TranslatedRightsType = "ReadKey"
                            }
                            Else {
                                $TranslatedRightsType = "Read"
                            }
                        }
                        -1610612736 {
                            If ($CurrentRightsType -eq "RegistryRights") {
                                $TranslatedRightsType = "ReadKey"
                            }
                            Else {
                                $TranslatedRightsType = "ReadAndExecute"
                            }
                        }
                        1073741824 {
                            $TranslatedRightsType = "Write"
                        }
                        268435456 {
                            $TranslatedRightsType = "FullControl"
                        }
                    }
                }
                Else {
                    $TranslatedRightsType = $Obj.$CurrentRightsType
                }

                $NewObj = [PSCustomObject]@{
                    $($CurrentRightsType) = $TranslatedRightsType
                    AccessControlType     = $($Obj.AccessControlType)
                    IdentityReference     = $($Obj.IdentityReference)
                    IsInherited           = $($Obj.IsInherited)
                    InheritanceFlags      = $($Obj.InheritanceFlags)
                    PropagationFlags      = $($Obj.PropagationFlags)
                }
                $TranslatedACL.Add($NewObj)
            }

            #----------------------------------------------
            #Combine split ACLs and update $CurrentACL
            #----------------------------------------------
            $AclList = New-Object System.Collections.Generic.List[System.Object]
            $UniqueIDs = $TranslatedACL.IdentityReference | Select-Object -Unique
            ForEach ($ID in $UniqueIDs) {
                #Used to grab unique IdentityReference
                $Rule = ($TranslatedACL | Where-Object { ($_.IdentityReference -eq $ID) -and (($_.InheritanceFlags -eq "ContainerInherit" -and $_.PropagationFlags -eq "InheritOnly") -or ($_.InheritanceFlags -eq "None" -and $_.PropagationFlags -eq "None")) }) #Query for split ACLs
                If (($Rule | Measure-Object).Count -eq 2) {
                    #If the ACL is split (this key only + subkeys only)
                    #If the two records match in all but InhertianceFlags and PropagationFlags
                    If (($Rule[0].$CurrentRightsType -eq $Rule[1].$CurrentRightsType) -and ($Rule[0].IsInherited -eq $Rule[1].IsInherited) -and ($Rule[0].AccessControlType -eq $Rule[1].AccessControlType)) {
                        #New Combined ACL object (Applies to this key and subkeys)
                        $NewObj = [PSCustomObject]@{
                            $($CurrentRightsType) = $Rule[0].$CurrentRightsType
                            AccessControlType     = $Rule[0].AccessControlType
                            IdentityReference     = $Rule[0].IdentityReference
                            IsInherited           = $Rule[0].IsInherited
                            InheritanceFlags      = "ContainerInherit"
                            PropagationFlags      = "None"
                        }
                        $AclList.Add($NewObj)
                    }
                }
                Else {
                    $Rule = ($TranslatedACL | Where-Object { ($_.IdentityReference -eq $ID) })
                    ForEach ($r in $Rule) {
                        $NewObj = [PSCustomObject]@{
                            $($CurrentRightsType) = $($r.$CurrentRightsType)
                            AccessControlType     = $($r.AccessControlType)
                            IdentityReference     = $($r.IdentityReference)
                            IsInherited           = $($r.IsInherited)
                            InheritanceFlags      = $($r.InheritanceFlags)
                            PropagationFlags      = $($r.PropagationFlags)
                        }
                        $AclList.Add($NewObj)
                    }
                }
            }

            #--------------------------
            #Proceed as normal
            #--------------------------
            # Look for missing default rules
            ForEach ($Object in $DefaultAcl) {
                If ($Object.Mandatory -eq $true -and (-Not($AclList | Where-Object { ($_.IdentityReference -eq $Object.IdentityReference) -and ($_.$($CurrentRightsType) -eq $Object.$($DefaultRightsType)) -and ($_.AccessControlType -eq $Object.AccessControlType) -and ($_.InheritanceFlags -eq $Object.InheritanceFlags) -and ($_.PropagationFlags -in $Object.PropagationFlags) }))) {
                    $IsDefault = $false
                    $AclObj = New-Object -TypeName PsObject
                    $AclObj | Add-Member -MemberType NoteProperty -Name "Reason" -Value "Missing Default Rule"
                    $AclObj | Add-Member -MemberType NoteProperty -Name "$($DefaultRightsType)" -Value $Object.$($DefaultRightsType)
                    $AclObj | Add-Member -MemberType NoteProperty -Name "AccessControlType" -Value $Object.AccessControlType
                    $AclObj | Add-Member -MemberType NoteProperty -Name "IdentityReference" -Value $Object.IdentityReference
                    $AclObj | Add-Member -MemberType NoteProperty -Name "IsInherited" -Value $Object.IsInherited
                    $AclObj | Add-Member -MemberType NoteProperty -Name "InheritanceFlags" -Value $Object.InheritanceFlags
                    $AclObj | Add-Member -MemberType NoteProperty -Name "PropagationFlags" -Value ($Object.PropagationFlags -Join " or ")
                    $AclFindings += $AclObj
                }
            }

            # Compare rules
            ForEach ($Object in $AclList) {
                If (-Not($DefaultAcl | Where-Object { ($_.IdentityReference -eq $Object.IdentityReference) -and ($_.$($DefaultRightsType) -contains $Object.$($CurrentRightsType)) -and ($_.AccessControlType -eq $Object.AccessControlType) -and ($_.InheritanceFlags -contains $Object.InheritanceFlags) -and ($_.PropagationFlags -contains $Object.PropagationFlags) })) {
                    # Look for unexpected rule
                    $IsDefault = $false
                    $AclObj = New-Object -TypeName PsObject
                    $AclObj | Add-Member -MemberType NoteProperty -Name "Reason" -Value "Non-Default Rule"
                    $AclObj | Add-Member -MemberType NoteProperty -Name "$($CurrentRightsType)" -Value $Object.$($CurrentRightsType)
                    $AclObj | Add-Member -MemberType NoteProperty -Name "AccessControlType" -Value $Object.AccessControlType
                    $AclObj | Add-Member -MemberType NoteProperty -Name "IdentityReference" -Value $Object.IdentityReference
                    $AclObj | Add-Member -MemberType NoteProperty -Name "IsInherited" -Value $Object.IsInherited
                    $AclObj | Add-Member -MemberType NoteProperty -Name "InheritanceFlags" -Value $Object.InheritanceFlags
                    $AclObj | Add-Member -MemberType NoteProperty -Name "PropagationFlags" -Value $Object.PropagationFlags
                    $AclFindings += $AclObj
                }
            }
        }
    }

    $AclResults.IsDefault = $IsDefault
    $AclResults.AclFindings = $AclFindings
    $AclResults.Acl = $AclList
    Return $AclResults
}

Function Get-CorporateComment {
    # Function for getting standarized comments from answer file.
    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$VulnID,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ErrorActionPreference = "SilentlyContinue"

    [hashtable]$AnswerResults = @{ }
    $AnswerResults.AFKey = ""
    $AnswerResults.AFComment = ""
    $AnswerResults.ExpectedStatus = ""
    $AnswerResults.AFStatus = ""

    If ($AnswerFile) {
        Try {
            [XML]$AnswerData = Get-Content -Path $AnswerFile
            If ($AnswerData.STIGComments.Vuln | Where-Object ID -EQ $VulnID | Select-Object -ExpandProperty AnswerKey | Where-Object Name -EQ $AnswerKey) {
                $AnswerObject = $AnswerData.STIGComments.Vuln | Where-Object ID -EQ $VulnID | Select-Object -ExpandProperty AnswerKey | Where-Object Name -EQ $AnswerKey
                $AnswerResults.AFKey = $AnswerKey
                $AnswerResults.ExpectedStatus = $AnswerObject.ExpectedStatus
                If (($AnswerObject.ValidationCode).Trim()) {
                    $Validated = (Invoke-Expression $AnswerObject.ValidationCode)
                    If ($Validated -eq $true) {
                        If ($AnswerObject.ValidTrueStatus -eq "") {
                            $AnswerResults.AFStatus = $AnswerObject.ExpectedStatus
                        }
                        Else {
                            $AnswerResults.AFStatus = $AnswerObject.ValidTrueStatus
                        }
                        $AnswerResults.AFComment = "[ValidTrueComment]:`r`n" + ($AnswerObject.ValidTrueComment).Replace('$UserSID', "$UserSID") | Out-String
                    }
                    Else {
                        If ($AnswerObject.ValidFalseStatus -eq "") {
                            $AnswerResults.AFStatus = $AnswerObject.ExpectedStatus
                        }
                        Else {
                            $AnswerResults.AFStatus = $AnswerObject.ValidFalseStatus
                        }
                        $AnswerResults.AFComment = "[ValidFalseComment]:`r`n" + ($AnswerObject.ValidFalseComment).Replace('$UserSID', "$UserSID") | Out-String
                    }
                }
                Else {
                    If ($AnswerObject.ValidTrueStatus -eq "") {
                        $AnswerResults.AFStatus = $AnswerObject.ExpectedStatus
                    }
                    Else {
                        $AnswerResults.AFStatus = $AnswerObject.ValidTrueStatus
                    }
                    $AnswerResults.AFComment = "[ValidTrueComment]:`r`n" + ($AnswerObject.ValidTrueComment).Replace('$UserSID', "$UserSID") | Out-String
                }

                # Add output of ValidationCode to Comment
                If ($Validated) {
                    $AnswerResults.AFComment += "`r`n[ValidationCodeOutput]:`r`n" + $($Validated | Out-String) | Out-String
                }
            }
            ElseIf ($AnswerData.STIGComments.Vuln | Where-Object ID -EQ $VulnID | Select-Object -ExpandProperty AnswerKey | Where-Object Name -EQ "DEFAULT") {
                $AnswerObject = $AnswerData.STIGComments.Vuln | Where-Object ID -EQ $VulnID | Select-Object -ExpandProperty AnswerKey | Where-Object Name -EQ "DEFAULT"
                $AnswerResults.AFKey = "DEFAULT"
                $AnswerResults.ExpectedStatus = $AnswerObject.ExpectedStatus
                If (($AnswerObject.ValidationCode).Trim()) {
                    $Validated = (Invoke-Expression $AnswerObject.ValidationCode)
                    If ($Validated -eq $true) {
                        If ($AnswerObject.ValidTrueStatus -eq "") {
                            $AnswerResults.AFStatus = $AnswerObject.ExpectedStatus
                        }
                        Else {
                            $AnswerResults.AFStatus = $AnswerObject.ValidTrueStatus
                        }
                        $AnswerResults.AFComment = "[ValidTrueComment]:`r`n" + ($AnswerObject.ValidTrueComment).Replace('$UserSID', "$UserSID") | Out-String
                    }
                    Else {
                        If ($AnswerObject.ValidFalseStatus -eq "") {
                            $AnswerResults.AFStatus = $AnswerObject.ExpectedStatus
                        }
                        Else {
                            $AnswerResults.AFStatus = $AnswerObject.ValidFalseStatus
                        }
                        $AnswerResults.AFComment = "[ValidFalseComment]:`r`n" + ($AnswerObject.ValidFalseComment).Replace('$UserSID', "$UserSID") | Out-String
                    }
                }
                Else {
                    If ($AnswerObject.ValidTrueStatus -eq "") {
                        $AnswerResults.AFStatus = $AnswerObject.ExpectedStatus
                    }
                    Else {
                        $AnswerResults.AFStatus = $AnswerObject.ValidTrueStatus
                    }
                    $AnswerResults.AFComment = "[ValidTrueComment]:`r`n" + ($AnswerObject.ValidTrueComment).Replace('$UserSID', "$UserSID") | Out-String
                }

                # Add output of ValidationCode to Comment
                If ($Validated) {
                    $AnswerResults.AFComment += "`r`n[ValidationCodeOutput]:`r`n" + $($Validated | Out-String) | Out-String
                }
            }
            Else {
                $AnswerResults = $null
            }
        }
        Catch {
            $AnswerResults = $null
            Write-Log $LogPath "    Answer file ValidationCode failed" $LogComponent "Error" -OSPlatform $OSPlatform
            Write-Log $LogPath "    Answer File: $AnswerFile" $LogComponent "Error" -OSPlatform $OSPlatform
            Write-Log $LogPath "    Answer Key: $AnswerKey" $LogComponent "Error" -OSPlatform $OSPlatform
            Write-Log $LogPath "    $($_.Exception.Message)" $LogComponent "Error" -OSPlatform $OSPlatform
        }
    }
    Return $AnswerResults
}

Function Get-AllInstances {
    # Generate list of valid instances.  Exclude SQL Server 2014 Express edition.
    $ValidInstances = New-Object System.Collections.Generic.List[System.Object]
    $KeysToCheck = @("HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server")
    ForEach ($Key in $KeysToCheck) {
        $Instances = (Get-ItemProperty $Key).InstalledInstances
        ForEach ($Instance in $Instances) {
            $p = (Get-ItemProperty "$($Key)\Instance Names\SQL").$Instance
            $Edition = (Get-ItemProperty "$($Key)\$($p)\Setup").Edition
            $Version = [Version](Get-ItemProperty "$($Key)\$($p)\Setup").Version
            If (-Not($Version -like "12.0*" -and $Edition -like "*Express*")) {
                $NewObj = [PSCustomObject]@{
                    InstanceName = $Instance
                    Edition      = $Edition
                    Version      = $Version
                }
                $ValidInstances.Add($NewObj)
            }
        }
    }

    # Get instance names and service status
    $allInstances = New-Object System.Collections.Generic.List[System.Object]
    $KeysToCheck = @("HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL")
    ForEach ($Key in $KeysToCheck) {
        If (Test-Path $Key) {
            (Get-Item $Key).GetValuenames() | Where-Object { $_ -notlike '*#*' } | ForEach-Object {
                If ($_ -in $ValidInstances.InstanceName) {
                    $Version = ($ValidInstances | Where-Object InstanceName -EQ $_).Version
                    If ($_ -eq 'MSSQLSERVER') {
                        If (Get-Service 'MSSQLSERVER' -ErrorAction SilentlyContinue) {
                            $Status = (Get-Service 'MSSQLSERVER').Status
                            $NewObj = [PSCustomObject]@{
                                Name    = $env:COMPUTERNAME
                                Service = "MSSQLSERVER"
                                Status  = $Status
                                Version = $Version
                            }
                        }
                        Else {
                            $NewObj = [PSCustomObject]@{
                                Name    = $env:COMPUTERNAME
                                Service = "NotFound"
                                Status  = "NA"
                                Version = $Version
                            }
                        }
                        $allInstances.Add($NewObj)
                    }
                    Else {
                        $instance = $_
                        $tsname = (Get-Item $Key).GetValue($instance)
                        If ($Key -like "*WOW6432Node*") {
                            If (Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\$tsname\cluster") {
                                $cname = (Get-Item "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\$tsname\cluster").GetValue('ClusterName')
                            }
                            Else {
                                $cname = $env:computername
                            }
                        }
                        Else {
                            If (Test-Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$tsname\cluster") {
                                $cname = (Get-Item "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$tsname\cluster").GetValue('ClusterName')
                            }
                            Else {
                                $cname = $env:computername
                            }
                        }

                        If (Get-Service "mssql`$$_" -ErrorAction SilentlyContinue) {
                            $Status = (Get-Service "mssql`$$_").Status
                            $NewObj = [PSCustomObject]@{
                                Name    = "$($cname)\$($instance)"
                                Service = "mssql`$$_"
                                Status  = $Status
                                Version = $Version
                            }
                        }
                        Else {
                            $NewObj = [PSCustomObject]@{
                                Name    = "$($cname)\$($instance)"
                                Service = "NotFound"
                                Status  = "NA"
                                Version = $Version
                            }
                        }
                        $allInstances.Add($NewObj)
                    }
                }
            }
        }
    }
    Return $allInstances
}

Function Get-InstanceVersion {
    param (
        [Parameter(Mandatory = $true)]
        [String]$Instance)

    $InstanceVersion = (Get-ISQL -ServerInstance "$Instance" -qry "select @@version").column1
    $null = $InstanceVersion -match "SQL Server \d{4}"
    $VersionToReturn = $Matches.Values -replace "[^0-9]"
    Return $VersionToReturn
}

function Get-ISQL {
    <#
        .SYNOPSIS
            Wrapper function for the invoke-sqlcmd cmdlet.
        .DESCRIPTION
            Get-ISQL facilitates running a SQL query against a server, or against a slew of servers.

            Environment variables $ALLSQLINSTANCES, $common_SQLINSTANCE and $common_SQLDB can tailor parameter behavior (see parameter descriptions).
        .PARAMETER qry
            [Optional] specifies a query to run against MSSQL.
        .PARAMETER InputFile
            [Optional] specifies a file of SQL to run.
        .PARAMETER ServerInstance
            [Optional] specifies the server/instance to query. Can also be "ALL" to run against all known instances (as defined by $ALLSQLINSTANCES). If omitted, then $common_SQLINSTANCE will be used, if defined, else all SQL instances on the local server will be queried.
        .PARAMETER Database
            [Optional] specifies the database to query. If omitted, then $common_SQLDB or "master" will be used. Can also specify "ALL" or "ALLUSER" to query all databases or all user databases on the instance.
        .PARAMETER Verbose
            Causes Get-ISQL to display the server/instance and database being queried.
        .INPUTS
            A SQL query can be piped to Get-ISQL in lieu of specifying the qry parameter.
        .EXAMPLE
            Get-ISQL -ServerInstance ALL 'select @@servername' -verbose
            Executes 'select @@servername' against each instance defined by $ALLSQLHOSTS, displaying the server/instance and database name prior to querying MSSQL.
            (This example is useful for ensuring the instances named in MSSQL match those used for making the connection.)
    #>
    param (
        # A valid SQL or DDL statement must either be piped in or specified via the qry parameter.
        [parameter(Mandatory = $false, ValueFromPipeline = $true)] [Alias('q')] [String] $qry
        , [Parameter(Mandatory = $false)] [ValidateScript( { Test-Path -LiteralPath $_ -ErrorAction $ea_ignore })] [Alias('f')] [string] $InputFile
        , [Alias('s')] [String[]] $ServerInstance
        , [Alias('d')] [String] $Database = "omitted"
    )

    $sRegistrySQL = 'hklm:\software\microsoft\microsoft sql server\instance names\sql'

    #####
    # Validate Parameters...

    # Validate Database
    if ($Database -eq 'omitted') {
        if (!(Test-Path variable:common_SQLDB)) {
            $mydb = 'master'
        }
        else {
            $mydb = $common_SQLDB
        }
    }
    else {
        $mydb = $Database
    }

    # Validate ServerInstance
    if ($ServerInstance -eq 'ALL' -and $ALLSQLINSTANCES) {
        $arrInstances = $ALLSQLINSTANCES
    }
    elseif ($ServerInstance -gt '') {
        $arrInstances = $ServerInstance
    }
    elseif (Test-Path variable:common_SQLINSTANCE) {
        $arrInstances = $common_SQLINSTANCE
    }
    else {
        # no instance specified, see if we can get one from the registry
        $arrInstances = @()
        (Get-Item $sRegistrySQL).getvaluenames() | Where-Object { $_ -notlike '*#*' } | ForEach-Object {
            if ( $_ -eq 'MSSQLSERVER' -and (Get-Service 'MSSQLSERVER').Status -eq 'Running' ) {
                $arrInstances += $env:COMPUTERNAME
            }
            elseif ( (Get-Service "mssql`$$_" -ErrorAction $ea_ignore).Status -eq 'Running') {
                $instance = $_
                $tsname = (Get-Item $sRegistrySQL).getValue($instance)
                if (Test-Path "HKLM:\software\microsoft\microsoft sql server\$tsname\cluster") {
                    $cname = (Get-Item "HKLM:\software\microsoft\microsoft sql server\$tsname\cluster").getvalue('ClusterName')
                }
                else {
                    $cname = $env:computername
                }
                $arrInstances += $cname + '\' + $instance
            }
        }
    }

    # Validate qry and InputFile
    if ( $qry -and $InputFile ) {
        throw('Either a query or an input file may be specified, but not both.')
    }
    elseif ( $InputFile ) {
        $filePath = $(Resolve-Path -LiteralPath $InputFile).path -replace '^.*::', ''
        $qry = [System.IO.File]::ReadAllText("$filePath")
    }
    elseif ( Test-Path -LiteralPath $qry -ErrorAction $ea_ignore) {
        if ($qry -like '*.sql') {
            # A filename was provided in the qry; reload qry with the file's content
            $filePath = $(Resolve-Path -LiteralPath $qry).path -replace '^.*::', ''
            Write-Debug "filepath = $filepath"
            $qry = [System.IO.File]::ReadAllText("$filePath")
        }
        else {
            throw('A filename was specified, but it did not have a .sql extension')
        }
    }
    elseif ( -not $qry ) {
        throw('Must specify either a query or an input file.')
    }

    # Run the SQL
    If ("TrustServerCertificate" -in (Get-Command Invoke-Sqlcmd).Parameters.Keys) {
        # -TrustServerCertificate is a valid parameter so use it.
        foreach ($i in $arrInstances) {
            if ($mydb -eq 'ALL') {
                $arrDB = (invoke-sqlcmd "select name from sys.databases where state = 0" -ServerInstance $i -TrustServerCertificate).Name
            }
            elseif ($mydb -eq 'ALLUSER') {
                $arrDB = (Invoke-Sqlcmd "select name from sys.databases where state = 0 and name not in ('Master','model','msdb','tempdb')" -ServerInstance $i -TrustServerCertificate).Name
            }
            else {
                $arrDB = $mydb
            }
            foreach ($db in $arrDB) {
                Write-Verbose "Running against server $i, database $db"
                invoke-sqlcmd -serverinstance $i -database $db -suppressProviderContextWarning -query $qry -querytimeout 65535 -TrustServerCertificate
            }
        }
    }
    Else {
        foreach ($i in $arrInstances) {
            if ($mydb -eq 'ALL') {
                $arrDB = (invoke-sqlcmd "select name from sys.databases where state = 0" -ServerInstance $i).Name
            }
            elseif ($mydb -eq 'ALLUSER') {
                $arrDB = (invoke-sqlcmd "select name from sys.databases where state = 0 and name not in ('Master','model','msdb','tempdb')" -ServerInstance $i).Name
            }
            else {
                $arrDB = $mydb
            }
            foreach ($db in $arrDB) {
                Write-Verbose "Running against server $i, database $db"
                invoke-sqlcmd -serverinstance $i -database $db -suppressProviderContextWarning -query $qry -querytimeout 65535
            }
        }
    }
}

function Confirm-TraceAuditSetting {
    <#
        .SYNOPSIS
            Examines a MSSQL server's trace and audit settings to verify STIG adherance.
        .DESCRIPTION
            Confirm-TraceAuditSettings will first determine whether audits or traces are being used, and then will inspect the configuration of the audits or traces to verify all required events are being audited.  A report of any un-audited events is returned as a string.
        .INPUTS
            None. Does not accept piped-in input.
        .OUTPUTS
            Returns a string detailing any findings.
    #>
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database
    )
    $ResultData = ""
    # Iterate through each of the servers on this instance...
    # 20201106 JJS Added Instance Database
    $servers = (Get-ISQL -ServerInstance $Instance -Database $Database 'select @@servername')
    if ($servers) {
        foreach ($instance in $servers.column1) {
            # First, check to see if the server is compliant in audits
            $res = Get-ISQL -serverinstance $instance "
      with q as (
              select 'APPLICATION_ROLE_CHANGE_PASSWORD_GROUP' as audit_action_name
        union select 'AUDIT_CHANGE_GROUP'
        union select 'BACKUP_RESTORE_GROUP'
        union select 'DATABASE_CHANGE_GROUP'
        union select 'DATABASE_OBJECT_CHANGE_GROUP'
        union select 'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP'
        union select 'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'
        union select 'DATABASE_OPERATION_GROUP'
        union select 'DATABASE_OWNERSHIP_CHANGE_GROUP'
        union select 'DATABASE_PERMISSION_CHANGE_GROUP'
        union select 'DATABASE_PRINCIPAL_CHANGE_GROUP'
        union select 'DATABASE_PRINCIPAL_IMPERSONATION_GROUP'
        union select 'DATABASE_ROLE_MEMBER_CHANGE_GROUP'
        union select 'DBCC_GROUP'
        union select 'FAILED_LOGIN_GROUP'
        union select 'LOGIN_CHANGE_PASSWORD_GROUP'
        union select 'LOGOUT_GROUP'
        union select 'SCHEMA_OBJECT_CHANGE_GROUP'
        union select 'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP'
        union select 'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP'
        union select 'SERVER_OBJECT_CHANGE_GROUP'
        union select 'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'
        union select 'SERVER_OBJECT_PERMISSION_CHANGE_GROUP'
        union select 'SERVER_OPERATION_GROUP'
        union select 'SERVER_PERMISSION_CHANGE_GROUP'
        union select 'SERVER_PRINCIPAL_CHANGE_GROUP'
        union select 'SERVER_PRINCIPAL_IMPERSONATION_GROUP'
        union select 'SERVER_ROLE_MEMBER_CHANGE_GROUP'
        union select 'SERVER_STATE_CHANGE_GROUP'
        union select 'SUCCESSFUL_LOGIN_GROUP'
        union select 'TRACE_CHANGE_GROUP'
       except
	          select audit_action_name
	            from sys.server_audit_specification_details d
			   inner join sys.server_audit_specifications s	on d.server_specification_id = s.server_specification_id
			   inner join sys.server_audits a on s.audit_guid = a.audit_guid
			   where s.is_state_enabled = 1
			     and a.is_state_enabled = 1
    )
    select @@SERVERNAME as InstanceName, Audit_Action_Name from q
    "
            if ($res) {
                # Deficiencies were found in the audits, check traces...
                $qry = "
        with q as (
                select 14 as eventid
          union select 15
          union select 18
          union select 20
          union select 102
          union select 103
          union select 104
          union select 105
          union select 106
          union select 107
          union select 108
          union select 109
          union select 110
          union select 111
          union select 112
          union select 113
          union select 115
          union select 116
          union select 117
          union select 118
          union select 128
          union select 129
          union select 130
          union select 131
          union select 132
          union select 133
          union select 134
          union select 135
          union select 152
          union select 153
          union select 170
          union select 171
          union select 172
          union select 173
          union select 175
          union select 176
          union select 177
          union select 178
      "
                Get-ISQL -serverinstance $instance 'select id from sys.traces' | ForEach-Object {
                    $qry += "except select eventid from sys.fn_trace_geteventinfo(" + $_.id + ") "
                }
                $qry += ")
        select @@SERVERNAME as InstanceName, eventid from q
      "
                $restrace = Get-ISQL -serverinstance $instance $qry
                if ($restrace) {
                    if ($ResultData -eq "") {
                        $ResultData = "The check found events that are not being audited by SQL traces:`n"
                    }
                    $ResultData += "$($restrace | Format-Table | Out-String)"
                }
            }
        }
    }
    Write-Output $ResultData
}

Function Get-AccessProblem (
    [parameter(mandatory = $true)][System.Security.AccessControl.AuthorizationRuleCollection]$CurrentAuthorizations
    , [parameter(mandatory = $true)][System.Collections.Hashtable]$AllowedAuthorizations
    , [parameter(mandatory = $true)][string]$FilePath
    , [parameter(mandatory = $true)][string]$InstanceName
    ) {
    Set-StrictMode -Version 2.0
    $fSQLAdminFull = $fSysAdminFull = $false
    $ResultData = ''

    function AppendResultData (
        [parameter(mandatory = $true)][ref]    $ResultData
        , [parameter(mandatory = $true)][string] $FilePath
        , [parameter(mandatory = $true)][string] $Message
    ) {
        Set-StrictMode -Version 2.0
        if ($ResultData.value -eq '') {
            $ResultData.value = "In directory ${FilePath}:`n`n"
        }
        $ResultData.value += "$Message`n"
    }

    $CurrentAuthorizations | ForEach-Object {
        $arrRights = $_.FileSystemRights -split ', *'
        $sUser = $_.IdentityReference.value
        if ($sUser -match "\`$${InstanceName}$") {
            # This is a service-based account (e.g. NT SERVER\SQLAgent$SQL01), replace the service w/ <INSTANCE> when checking the hash table...
            $sSearchUser = $sUser -replace "\`$${InstanceName}$", "$<INSTANCE>"
            $arrAuthPerms = $AllowedAuthorizations[$sSearchUser]
        }
        elseif ($sUser -eq 'NT SERVICE\MSSQLSERVER' -and $InstanceName -eq 'MSSQLSERVER' ) {
            $arrAuthPerms = $AllowedAuthorizations['NT SERVICE\MSSQL$<INSTANCE>']
        }
        else {
            $arrAuthPerms = $AllowedAuthorizations[$sUser]
        }

        try {
            $iAuth = ($arrAuthPerms | Measure-Object).count
        }
        catch {
            $iAuth = 0
        }

        if ($iAuth -gt 0) {
            if ('FullControl' -in $arrAuthPerms) {
                # This user is allowed FULL CONTROL, so no need to check further
                switch ($sUser) {
                    #$C_ACCT_SQLADMINS        { $fSQLAdminFull = $true } # JJS Removed
                    'BUILTIN\Administrators' {
                        $fSysAdminFull = $true
                    }
                }
            }
            else {
                # Let's try to identify perms held by the user, but not in the list of authorized perms
                $arrTemp = $arrRights -ne 'Synchronize' # Get a copy of rights assigned to the user, less 'Synchronize' which seems innocuous.
                foreach ($p in $arrAuthPerms) {
                    $arrTemp = $arrTemp -ne $p # rebuild the array without $p in it
                    foreach ($psub in get-subperm($p)) {
                        $arrTemp = $arrTemp -ne $p
                    }
                }
                if (($arrTemp | Measure-Object).count -gt 0) {
                    # We removed any permissions that were authorized, so the only ones left should be the unauthorized perms
                    AppendResultData ([ref]$ResultData) $FilePath "$sUser has $($arrTemp -join ',') rights (should be $($arrAuthPerms -ne 'Synchronize' -join ','))."
                }
                else {
                    if (! ($_.inheritanceflags -eq 'ContainerInherit, ObjectInherit' -and $_.propagationflags -eq 'None')) {
                        if (! ($FilePath -match '\.trc$' -or $FilePath -match '\.sqlaudit$')) {
                            AppendResultData ([ref]$ResultData) $FilePath "$sUser seems to have appropriate rights, but those rights are not properly propogated."
                        }
                    }
                }
            }
        }
        else {
            AppendResultData ([ref]$ResultData) $FilePath "$sUser has $($arrRights -join ',') rights (should be NO rights)."
        }
    }

    if ($fSQLAdminFull -and $fSysAdminFull) {
        # If we have a custom SQLAdmins group, then they should have full control and the built-in admin group should be read-only.
        AppendResultData ([ref]$ResultData) $FilePath "Both $C_ACCT_SQLADMINS and BUILTIN\Administrators have full control"
    }

    if ($ResultData -gt '') {
        $ResultData += "`n"
    }

    Return $ResultData
}

function Get-SubPerm {
    <#
        .SYNOPSIS
            Returns an array of file-access permissions that are included with the passed-in permission.
        .PARAMETER perm
            [Mandatory] A file-access permission.
        .INPUTS
            None. Get-SubPerm does not accept piped-in input.
        .OUTPUTS
            An array of permissions.
        .EXAMPLE
            Get-SubPerm 'ReadAndExecute'
            Returns all file access permissions that are included with 'ReadAndExecute'.
    #>
    param(
        [parameter(mandatory = $true)] [string] $perm
    )

    $hashSubPerms = @{
        'Modify'         = @('ReadAndExecute', 'Write', 'Delete')
        'Read'           = @('ReadData', 'ReadExtendedAttributes', 'ReadAttributes', 'ReadPermissions')
        'ReadAndExecute' = @('Read', 'ExecuteFile')
        'Write'          = @('WriteData', 'AppendData', 'WriteExtendedAttributes', 'WriteAttributes')
    }

    $arrResult = $arrPerms = $hashSubPerms[$perm]
    foreach ($p in $arrPerms) {
        $arr = get-SubPerm($p);
        try {
            $iCnt = ($arr | Measure-Object).count
        }
        catch {
            $iCnt = 0
        }

        if ($iCnt -gt 0) {
            $arrResult += $arr
        }
    }
    return $arrResult
}

function Get-SqlVersion {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Instance
    )

    $res = Get-ISQL -ServerInstance $Instance -Database "Master" "select @@version"

    $sqlVersion = ""
    if ($res.column1 -like "Microsoft SQL Server 2014*") {
        $sqlVersion = "120"
    }
    elseif ($res.column1 -like "Microsoft SQL Server 2016*") {
        $sqlVersion = "130"
    }
    elseif ($res.column1 -like "Microsoft SQL Server 2017*") {
        $sqlVersion = "140"
    }
    elseif ($res.column1 -like "Microsoft SQL Server 2019*") {
        $sqlVersion = "150"
    }
    elseif ($res.column1 -like "Microsoft SQL Server 2022*") {
        $sqlVersion = "160"
    }
    return $sqlVersion
}

function Get-SqlVersionInstance {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Instance
    )

    $sqlVersion = Get-SqlVersion $Instance
    #$sqlVersionInstance = left($sqlVersion,2)+$Instance
    #$sqlVersionInstance = $sqlVersion.Substring(0,2)
    #$sqlVersionInstance = "MSSQL"+$sqlVersion.Substring(0,2)+".$instance"
    # need to remove hostname\
    $HostName = (Get-CimInstance Win32_Computersystem).name
    $InstanceOnly = $Instance.Replace($HostName + "\", "")
    $sqlVersionInstance = "MSSQL" + $sqlVersion.Substring(0, 2) + ".$instanceOnly"
    return $sqlVersionInstance
}


function Get-SqlProductFeatures {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $false)]
        [String]$Database = "master"
    )

    $sqlVersion = Get-SqlVersion $Instance

    $SqlInstallSummaryFile = "$env:programfiles\Microsoft SQL Server\$sqlVersion\Setup Bootstrap\Log\Summary.txt"

    $ProductFeaturesLineCount = 0
    $ProductFeatures = "Using file ($SqlInstallSummaryFile) for SQL Product Features.`n"

    if (Test-Path -Path $SqlInstallSummaryFile) {
        # read SqlInstallSummaryFile for section "Product features discovered:"
        try {
            $SqlInstallSummaryFileLines = Get-Content "$SqlInstallSummaryFile"

            $ProductFeaturesFound = $false

            foreach ($SqlInstallSummaryFileLine in $SqlInstallSummaryFileLines) {
                if ($SqlInstallSummaryFileLine -like "Product features discovered*" -or $ProductFeaturesFound -eq $True) {
                    $ProductFeaturesFound = $true
                    if ($ProductFeaturesFound -eq $true) {
                        if ($SqlInstallSummaryFileLine -like "Package properties*" ) {
                            break
                        }
                        else {
                            $ProductFeaturesLineCount += 1
                            $ProductFeatures += $SqlInstallSummaryFileLine + "`n"
                        }
                    }
                }
            }

            If ($ProductFeaturesLineCount -eq 0) {
                $ProductFeatures = "ERROR: No SQL Product Features Found in File ($SqlInstallSummaryFile)"
            }

        }
        catch {
            $ProductFeatures = "ERROR: Reading SQL Product Features File ($SqlInstallSummaryFile)"
        }
    }
    else {
        $ProductFeatures = "ERROR: Could not find SQL Product Features File ($SqlInstallSummaryFile)"
    }

    return $ProductFeatures
}

function Get-LeftNumbers {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$StringToScan
    )

    $returnValue = ""
    for ($i = 0; $i -lt $StringToScan.Length; $i++) {
        if ($StringToScan[$i] -like "[0-9]*") {
            $returnValue += $StringToScan[$i]
        }
        else {
            break
        }
    }
    return $returnValue
}

############################################################
## Apache Functions                                        #
############################################################

function Get-ApacheUnixExecutablePaths {
    $Command = "netstat -pant | grep LISTEN | awk '{print `$7}' | grep -Pv `"^-`$`" | awk -F`"/`" `'{print `$1}`'"
    $ListenPids = @(Invoke-Expression -Command $Command)

    $Executables = [System.Collections.ArrayList]@()
    foreach ($listenPid in $ListenPids) {
        $binCommand = "readlink /proc/$($listenPid)/exe"
        $bin = Invoke-Expression -Command $binCommand

        $binInfoCommand = "timeout 2s $($bin) -v 2>&1 | grep -Pi `"^Server\s*version:\s*Apache/2\.4`""
        $binInfo = Invoke-Expression -Command $binInfoCommand

        if ([string]::IsNullOrEmpty($binInfo)) {
            continue
        }

        [void]$Executables.Add($bin.Trim())
    }

    return $Executables
}

function Test-IsApacheInstalled {
    param (
        [Parameter(Mandatory)]
        [string] $OnOS
    )

    $STIGRequired = $false
    Try {
        if ($OnOS -eq "Unix") {
            if (-not ($IsLinux)) {
                return $STIGRequired
            }

            $ExecutablePaths = Get-ApacheUnixExecutablePaths
            if (($ExecutablePaths | Measure-Object).Count -gt 0) {
                $STIGRequired = $True
            }

            return $STIGRequired
        }
        elseif ($OnOS -eq "Windows") {
            if ($IsLinux) {
                return $STIGRequired
            }

            $Services = Get-CimInstance -ClassName win32_service
            If ($null -eq $Services) {
                Return $STIGRequired
            }

            Foreach ($service in $Services) {
                $PathName = $service.PathName
                $Path = ($PathName -split '"')[1]
                If ($null -eq $Path -or $Path -eq "") {
                    # If a path can't be parsed (because we know what it looks like) ignore.
                    Continue
                }

                If (-not (Test-Path -Path $Path -PathType Leaf)) {
                    # If a path is parsed and it doesn't lead to a file, ignore.
                    Continue
                }

                $Extension = (Get-ItemProperty -Path $Path -Name Extension).Extension
                If ($Extension -ne '.exe') {
                    # If the file is not an .exe, ignore.
                    Continue
                }

                $VersionInfo = (Get-Item -Path $Path).VersionInfo;
                $FileDescription = $VersionInfo.FileDescription;
                If ($FileDescription -notlike "*Apache*HTTP*Server") {
                    # If the file descriptor is not anything related to apache server, ignore.
                    Continue
                }

                $Param = '-v'
                $VersionOutput = (& "$($Path)" $Param)
                If ($VersionOutput | Select-String -Pattern '2.4' -Quiet) {
                    # If we get no version as output or if the version is incorrect, ignore.
                    $STIGRequired = $true
                }
            }
        }

        Return $STIGRequired
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

function Get-ApacheVersionTable {
    param (
        [Parameter(Mandatory)]
        [string] $ExecutablePath
    )

    $Param = '-V'
    $Version = & "$ExecutablePath" $Param

    return $Version
}

function Get-ConfigFilePaths {
    param (
        [Parameter(Mandatory)]
        [string] $ExecutablePath
    )

    $Param = '-t'
    $Param2 = '-D'
    $Param3 = 'DUMP_INCLUDES'
    $Configs = & "$ExecutablePath" $Param $Param2 $Param3

    $ConfigArray = [System.Collections.ArrayList]@()
    foreach ($string in $Configs) {
        if ($string | Select-String -SimpleMatch 'Included configuration files') {
            continue
        }

        # Get rid of those weird numbers before the path and preserve numbers in the path.
        # Example '(*) C:\Program Files (x86)\blah\blahblah' is converted to 'C:\Program Files (x86)\blah\blahblah'
        $Filtered = $string -replace '^\s*\(\*\)|^\s*\(\d+\)'
        $MoreFiltered = $Filtered.Trim().Replace('\', '/')
        if ($ConfigArray.Contains($MoreFiltered)) {
            continue
        }

        [void]$ConfigArray.Add($MoreFiltered)
    }

    return $ConfigArray
}

function Get-HttpdRootPath {
    param (
        [Parameter(Mandatory)]
        [string] $ExecutablePath
    )

    $Param = '-S'
    $Output = & "$ExecutablePath" $Param
    $HttpdRootPath = (($Output | Select-String "ServerRoot" | Out-String).Split('"')[1]).Replace('/', '\')
    $HttpdRootPath = $HttpdRootPath + '\'
    $Formatted = $HttpdRootPath.Replace('\\', '\')

    return $Formatted.Trim().Replace('\', '/')
}

function Get-RootServerConfigFile {
    param (
        [Parameter(Mandatory)]
        [string] $ExecutablePath
    )

    $HttpdRootPath = Get-HttpdRootPath -ExecutablePath $ExecutablePath
    $VersionTable = Get-ApacheVersionTable -ExecutablePath $ExecutablePath
    $RootServerConfigFile = (($VersionTable | Select-String -Pattern "SERVER_CONFIG_FILE" | Out-String).Split('"')[1]).Replace('/', '\')
    $RootServerConfigFile = $HttpdRootPath + $RootServerConfigFile
    $Formatted = $RootServerConfigFile.Replace('\\', '\')

    return $Formatted.Trim().Replace('\', '/')
}

function Get-Modules {
    param (
        [Parameter(Mandatory)]
        [string] $ExecutablePath
    )

    $Param = '-M'
    $Modules = & "$ExecutablePath" $Param

    return $Modules
}

function Get-VirtualHosts {
    param (
        [Parameter(Mandatory)]
        [string] $ExecutablePath
    )

    $Param = '-t'
    $Param2 = '-D'
    $Param3 = 'DUMP_VHOSTS'
    $VirtualHosts = & "$ExecutablePath" $Param $Param2 $Param3

    $Index = 0
    $VirtualHostArray = [System.Collections.ArrayList]@()
    $AddedVhosts = [System.Collections.ArrayList]@()
    foreach ($line in $VirtualHosts) {
        $IsHeader = $line | Select-String -Pattern "VirtualHost configuration" -Quiet
        if ($IsHeader -eq $true ) {
            continue
        }

        # Get the Path and
        $Original = $line -replace '(^.*\()', '' -replace '[()]', ''
        if ($IsLinux) {
            $Path = $Original.Split(':')[0]
            $LineNumber = $Original.Split(':')[1]
        }
        else {
            $Path = $Original.Split(':')[0] + ':' + $Original.Split(':')[1]
            $LineNumber = $Original.Split(':')[2]
        }

        if (-not(Test-Path -Path $Path -PathType Leaf)) {
            continue
        }

        if ($AddedVhosts.Contains($Original.ToString())) {
            continue
        }

        $TotalLines = (Get-Content -Path $Path).Length + 1
        $StartingLine = $TotalLines - $LineNumber
        $fileData = Get-Content -Path $Path -Tail $StartingLine

        $LineInFile = $LineNumber - 1
        $startPrinting = $false
        $LinesInBlock = [System.Collections.ArrayList]@()
        foreach ($line in $fileData) {
            $LineInFile++

            $isEnd = $line | Select-String -Pattern "\<\/VirtualHost>" | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -ne $isEnd -and $isEnd -ne "") {
                $startPrinting = $false
                $BlockLine = [PSCustomObject]@{
                    LineNumber = $LineInFile
                    Line       = $line
                }
                [void]$LinesInBlock.Add($BlockLine)
                break
            }

            $isStart = $line | Select-String -Pattern "\<VirtualHost.*\>" | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -ne $isStart -and $isStart -ne "") {
                $startPrinting = $true

                $SitePortLine = $line -replace '^\<VirtualHost\s+', '' -replace '>', ''
                $SitePortArray = $SitePortLine.Split(':')

                $SiteName = ($SitePortArray[0]).Trim()
                if ($SiteName -eq "*") {
                    $SiteName = "_default_"
                }

                $SitePort = ($SitePortArray[1]).Trim()
            }

            if ($startPrinting -eq $true) {
                $BlockLine = [PSCustomObject]@{
                    LineNumber = $LineInFile
                    Line       = $line
                }
                [void]$LinesInBlock.Add($BlockLine)
            }
        }

        $VirtualHostObject = [PSCustomObject]@{
            SiteName           = $SiteName
            SitePort           = $SitePort
            Index              = $Index
            ConfigFile         = $Path
            StartingLineNumber = $LineNumber
            Block              = $LinesInBlock
        }

        [void]$AddedVhosts.Add($Original.ToString())
        [void]$VirtualHostArray.Add($VirtualHostObject)
        $Index++
    }

    $RootPath = Get-RootServerConfigFile $ExecutablePath
    $VirtualHostObject = [PSCustomObject]@{
        Index              = -1
        ConfigFile         = $RootPath
        StartingLineNumber = -1
        Block              = ""
    }

    [void]$VirtualHostArray.Add($VirtualHostObject)

    # Add Root Server as additional VHOST.
    return $VirtualHostArray
}

function Get-ApacheSites {
    $Index = 1
    $ApacheObjects = [System.Collections.ArrayList]@()
    $ExecutablePaths = [System.Collections.ArrayList]@()
    if ($IsLinux) {
        $ExecutablePaths = Get-ApacheUnixExecutablePaths
    }
    else {
        $ApacheServices = Get-CimInstance -Class Win32_Service | Where-Object { $_.Name -like '*Apache*' }
        foreach ($service in $ApacheServices) {
            $ExecutablePath = $service.PathName.Split('"')[1]
            if ($ExacutablePath -eq "") {
                continue
            }

            if (-not (Test-Path -Path $ExecutablePath -PathType Leaf)) {
                # If the path parsed from the PathName is not a valid path does not lead to a file.
                continue
            }

            [void]$ExecutablePaths.Add($ExecutablePath)
        }
    }

    foreach ($executablePath in $ExecutablePaths) {
        $HttpdRootPath = Get-HttpdRootPath -ExecutablePath $executablePath
        $RootServerConfigFile = Get-RootServerConfigFile -ExecutablePath $executablePath
        $ConfigFilePaths = Get-ConfigFilePaths -ExecutablePath $executablePath
        $Modules = Get-Modules -ExecutablePath $executablePath
        $VirtualHosts = Get-VirtualHosts -ExecutablePath $executablePath

        $ApacheInstance = [PSCustomObject]@{
            Index                = $Index
            ExecutablePath       = $executablePath
            HttpdRootPath        = $HttpdRootPath
            RootServerConfigFile = $RootServerConfigFile
            ConfigFilePaths      = $ConfigFilePaths
            Modules              = $Modules
            VirtualHosts         = $VirtualHosts
        }

        [void]$ApacheObjects.Add($ApacheInstance)
        $Index++
    }

    return $ApacheObjects
}

function Get-ApacheModule {
    param (
        [Parameter(Mandatory)]
        [psobject] $ApacheInstance,
        [Parameter(Mandatory)]
        [string] $ModuleName
    )

    $Status = "Disabled"
    $ConfigFileLine = "Not Found"
    $LineNumber = "Not Found"
    $ConfigFile = "Not Found"

    if ($null -eq $ApacheInstance) {

        $Module = [PSCustomObject]@{
            Name           = $ModuleName
            Status         = $Status # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
            ConfigFileLine = $ConfigFileLine # Actual Line in the config file
            LineNumber     = $LineNumber
            ConfigFile     = $ConfigFile # Absolute File path
        }

        return $Module
    }

    $ModuleFound = $ApacheInstance.Modules | Select-String -Pattern $ModuleName
    if ($null -eq $ModuleFound -or $ModuleFound -eq "") {
        $Status = "Disabled"
    }
    else {
        $Status = "Enabled"
    }

    # Check the config files to see if the LoadModule Line with the module name is present.
    $Pattern = "LoadModule\b\s*$($ModuleName)\b"
    foreach ($aConfigFile in $ApacheInstance.ConfigFilePaths) {

        $Test = Select-String -Path $aConfigFile -Pattern $Pattern | Select-String -Pattern '^\s{0,}#' -NotMatch #| Select-Object -ExpandProperty Line,LineNumber
        if ($null -eq $Test -or $Test -eq "") {
            continue
        }

        $ConfigFileLine = $Test.Line
        $LineNumber = $Test.LineNumber
        $ConfigFile = $aConfigFile
        break
    }

    $Module = [PSCustomObject]@{
        Name           = $ModuleName
        Status         = $Status # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
        ConfigFileLine = $ConfigFileLine # Actual Line in the config file
        LineNumber     = $LineNumber
        ConfigFile     = $ConfigFile # Absolute File path
    }

    return $Module
}

function Get-ApacheDirectiveFromGlobalConfig {
    param (
        [Parameter(Mandatory)]
        [psobject] $ApacheInstance,
        [Parameter(Mandatory)]
        [string] $DirectiveName
    )

    $Status = "Not Found"
    $ConfigFileLine = "Not Found"
    $LineNumber = "Not Found"
    $ConfigFile = "Not Found"

    $FoundCount = 0
    $Pattern = "^\s*$($DirectiveName)\b.*$"
    $BackslashPattern = '\\$'
    $DirectivesFound = [System.Collections.ArrayList]@()
    foreach ($aConfigFile in $ApacheInstance.ConfigFilePaths) {
        $LineInFile = 0
        $startReading = $true
        $LineContinues = $false
        foreach ($line in Get-Content -Path $aConfigFile) {
            $LineInFile++

            $isStart = $line | Select-String -Pattern "\<VirtualHost.*\>" | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -ne $isStart -and $isStart -ne "") {
                $startReading = $false
            }

            $isEnd = $line | Select-String -Pattern "\<\/VirtualHost>" | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -ne $isEnd -and $isEnd -ne "") {
                $startReading = $true
                continue
            }

            if ($startReading -eq $true) {
                # This is where we would check for the directive.
                $Test = $line | Select-String -Pattern $Pattern | Select-String -Pattern '^\s{0,}#' -NotMatch
                $EOLBackslash = $line | Select-String -Pattern $BackslashPattern | Select-String -Pattern '^\s{0,}#' -NotMatch
                if ($null -eq $Test -or $Test -eq "") {
                    if ($LineContinues -eq $true) {
                        $line = $line -replace $BackslashPattern, ""
                        $Directive.ConfigFileLine += $line
                        $LineContinues = $false
                        if ( $null -ne $EOLBackslash -and $EOLBackslash -ne "") {
                            $LineContinues = $true
                        }
                    }
                }
                else {
                    #The directive exists
                    $Directive = [PSCustomObject]@{
                        Name           = $DirectiveName
                        Status         = "Found" # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
                        ConfigFileLine = $line.Trim() # Actual Line in the config file
                        LineNumber     = $LineInFile
                        ConfigFile     = $aConfigFile # Absolute File path
                        VirtualHost    = $null
                    }
                    [void]$DirectivesFound.Add($Directive)
                    $FoundCount++

                    if ( $null -ne $EOLBackslash -and $EOLBackslash -ne "") {
                        $LineContinues = $true
                        $Directive.ConfigFileLine = $Directive.ConfigFileLine -replace $BackslashPattern, ""
                    }
                }
            }
        }
    }

    #IF we STILL haven't found anything. Use our default values of not found.
    if ($FoundCount -le 0) {
        $Directive = [PSCustomObject]@{
            Name           = $DirectiveName
            Status         = $Status # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
            ConfigFileLine = $ConfigFileLine # Actual Line in the config file
            LineNumber     = $LineNumber
            ConfigFile     = $ConfigFile # Absolute File path
            VirtualHost    = $null
        }
        [void]$DirectivesFound.Add($Directive)
    }

    return $DirectivesFound
}

function Get-ApacheBlockFromGlobalConfig {
    param (
        [Parameter(Mandatory)]
        [psobject] $ApacheInstance,
        [Parameter(Mandatory)]
        [string] $BlockStart,
        [Parameter(Mandatory)]
        [string] $BlockEnd,
        [Parameter(Mandatory)]
        [string] $DirectiveName
    )

    $Status = "Not Found"
    $ConfigFileLine = "Not Found"
    $LineNumber = "Not Found"
    $ConfigFile = "Not Found"

    $Pattern = "^\s*$($DirectiveName)\b.*$"
    $DirectivesFound = [System.Collections.ArrayList]@()
    foreach ($aConfigFile in $ApacheInstance.ConfigFilePaths) {
        $LineInFile = 0
        $startReading = $true
        foreach ($line in Get-Content -Path $aConfigFile) {
            $LineInFile++

            $isStart = $line | Select-String -Pattern "\<VirtualHost.*\>" | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -ne $isStart -and $isStart -ne "") {
                $startReading = $false
                Continue
            }

            $isEnd = $line | Select-String -Pattern "\<\/VirtualHost>" | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -ne $isEnd -and $isEnd -ne "") {
                $startReading = $true
                continue
            }

            if ($startReading -eq $true) {
                $isBlockStart = $line | Select-String -Pattern "\<$BlockStart.*\>" | Select-String -Pattern '^\s{0,}#' -NotMatch
                if ($null -ne $isBlockStart -and $isBlockStart -ne "") {
                    $inBlock = $true
                }

                if ($inBlock -eq $true) {
                    # This is where we would check for the directive.
                    $found = $line | Select-String -Pattern $Pattern | Select-String -Pattern '^\s{0,}#' -NotMatch
                    if ($null -ne $found -and $found -ne "") {
                        $Directive = [PSCustomObject]@{
                            Name           = $DirectiveName
                            Status         = "Found" # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
                            ConfigFileLine = $line.Trim() # Actual Line in the config file
                            LineNumber     = $LineInFile
                            ConfigFile     = $aConfigFile # Absolute File path
                            VirtualHost    = $null
                        }
                        [void]$DirectivesFound.Add($Directive)
                    }

                    $isEnd = $line | Select-String -Pattern "\<\/$BlockEnd>" | Select-String -Pattern '^\s{0,}#' -NotMatch
                    if ($null -ne $isEnd -and $isEnd -ne "") {
                        $inBlock = $false
                    }
                }
            }
        }
    }

    #IF we STILL haven't found anything. Use our default values of not found.
    if (($DirectivesFound | Measure-Object).Count -le 0) {
        $Directive = [PSCustomObject]@{
            Name           = $DirectiveName
            Status         = $Status # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
            ConfigFileLine = $ConfigFileLine # Actual Line in the config file
            LineNumber     = $LineNumber
            ConfigFile     = $ConfigFile # Absolute File path
            VirtualHost    = $null
        }
        [void]$DirectivesFound.Add($Directive)
    }

    return $DirectivesFound
}

function Get-ApacheDirectiveFromVirtualBlock {
    param (
        [Parameter(Mandatory)]
        [psobject] $VirtualHost,
        [Parameter(Mandatory)]
        [string] $DirectiveName
    )

    $Status = "Not Found"
    $ConfigFileLine = "Not Found"
    $LineNumber = "Not Found"
    $ConfigFile = "Not Found"

    $FoundCount = 0
    $Pattern = "^\s*$($DirectiveName)\b.*$"
    $BackslashPattern = '\\$'
    $DirectivesFound = [System.Collections.ArrayList]@()
    if ($VirtualHost.Index -ne -1) {
        # We need to check the Virtual Host Block
        $LineContinues = $false
        foreach ($line in $VirtualHost.Block) {
            $Test = $line.Line | Select-String -Pattern $Pattern | Select-String -Pattern '^\s{0,}#' -NotMatch
            $EOLBackslash = $line.Line | Select-String -Pattern $BackslashPattern | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -eq $Test -or $Test -eq "") {
                if ($LineContinues -eq $true) {
                    $line.Line = $line.Line -replace $BackslashPattern, ""
                    $Directive.ConfigFileLine += $line.Line
                    $LineContinues = $false
                    if ( $null -ne $EOLBackslash -and $EOLBackslash -ne "") {
                        $LineContinues = $true
                    }
                }
                continue
            }

            $Directive = [PSCustomObject]@{
                Name           = $DirectiveName
                Status         = "Found" # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
                ConfigFileLine = $line.Line.Trim() # Actual Line in the config file
                LineNumber     = $line.LineNumber
                ConfigFile     = $VirtualHost.ConfigFile # Absolute File path
                VirtualHost    = $VirtualHost
            }
            [void]$DirectivesFound.Add($Directive)
            $FoundCount++

            if ( $null -ne $EOLBackslash -and $EOLBackslash -ne "") {
                $LineContinues = $true
                $Directive.ConfigFileLine = $Directive.ConfigFileLine -replace $BackslashPattern, ""
            }

        }
    }

    if ($FoundCount -le 0) {
        $Directive = [PSCustomObject]@{
            Name           = $DirectiveName
            Status         = $Status # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
            ConfigFileLine = $ConfigFileLine # Actual Line in the config file
            LineNumber     = $LineNumber
            ConfigFile     = $ConfigFile # Absolute File path
            VirtualHost    = $VirtualHost
        }
        [void]$DirectivesFound.Add($Directive)
    }

    return $DirectivesFound
}

function Get-ApacheBlockFromVirtualBlock {
    param (
        [Parameter(Mandatory)]
        [psobject] $VirtualHost,
        [Parameter(Mandatory)]
        [string] $BlockStart,
        [Parameter(Mandatory)]
        [string] $BlockEnd,
        [Parameter(Mandatory)]
        [string] $DirectiveName
    )

    $Status = "Not Found"
    $ConfigFileLine = "Not Found"
    $LineNumber = "Not Found"
    $ConfigFile = "Not Found"

    $FoundCount = 0
    $foundit = $false
    $inBlock = $false
    $Pattern = "^\s*$($DirectiveName)\b.*$"
    $DirectivesFound = [System.Collections.ArrayList]@()
    foreach ($line in $VirtualHost.Block) {
        $isStart = $line.line | Select-String -Pattern "\<$BlockStart.*\>" | Select-String -Pattern '^\s{0,}#' -NotMatch
        if ($null -ne $isStart -and $isStart -ne "") {
            $inBlock = $true
            $foundIt = $false
            Continue
        }

        if ($inBlock -eq $true) {
            # This is where we would check for the directive.
            $found = $line.line | Select-String -Pattern $Pattern | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -ne $found -and $found -ne "") {
                $foundIt = $true

                $Directive = [PSCustomObject]@{
                    Name           = $DirectiveName
                    Status         = "Found" # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
                    ConfigFileLine = $line.Line.Trim() # Actual Line in the config file
                    LineNumber     = $line.LineNumber
                    ConfigFile     = $VirtualHost.ConfigFile # Absolute File path
                    VirtualHost    = $VirtualHost
                }
                [void]$DirectivesFound.Add($Directive)
                $FoundCount++
            }

            $isEnd = $line.line | Select-String -Pattern "\<\/$BlockEnd>" | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -ne $isEnd -and $isEnd -ne "") {
                $inBlock = $false

                if ($foundIt -eq $false) {
                    $Directive = [PSCustomObject]@{
                        Name           = $DirectiveName
                        Status         = "Not Found" # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
                        ConfigFileLine = $ConfigFileLine
                        LineNumber     = $Linenumber
                        ConfigFile     = $VirtualHost.ConfigFile # Absolute File path
                        VirtualHost    = $VirtualHost
                    }
                    [void]$DirectivesFound.Add($Directive)
                }
            }
        }
    }

    if ($FoundCount -le 0) {
        $Directive = [PSCustomObject]@{
            Name           = $DirectiveName
            Status         = $Status # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
            ConfigFileLine = $ConfigFileLine # Actual Line in the config file
            LineNumber     = $LineNumber
            ConfigFile     = $ConfigFile # Absolute File path
            VirtualHost    = $VirtualHost
        }
        [void]$DirectivesFound.Add($Directive)
    }

    return $DirectivesFound
}

function Get-ApacheDirective {
    param (
        [Parameter(Mandatory)]
        [psobject] $ApacheInstance,
        [Parameter(Mandatory)]
        [AllowNull()]
        [psobject] $VirtualHost,
        [Parameter(Mandatory)]
        [string] $DirectiveName
    )

    $DirectivesFound = [System.Collections.ArrayList]@()
    if ($null -eq $VirtualHost) {
        # This will always be a server check.
        $DirectivesInGlobalConfig = [System.Collections.ArrayList]@(Get-ApacheDirectiveFromGlobalConfig -ApacheInstance $ApacheInstance -DirectiveName $DirectiveName)
        $DirectivesFound.AddRange($DirectivesInGlobalConfig)
        foreach ($vhost in $ApacheInstance.VirtualHosts) {
            if ($vhost.Index -eq -1) {
                continue
            }

            $DirectivesInVirtualHosts = [System.Collections.ArrayList]@(Get-ApacheDirectiveFromVirtualBlock -VirtualHost $vhost -DirectiveName $DirectiveName)
            $DirectivesFound.AddRange($DirectivesInVirtualHosts)
        }
    }
    else {
        $FoundCount = 0

        # This will execute if you pass in a Virtual Host to the funciton.
        # Check the Virtual Host for the Directive first.
        if ($VirtualHost.Index -ne -1) {
            $DirectivesInVirtualHosts = [System.Collections.ArrayList]@(Get-ApacheDirectiveFromVirtualBlock -VirtualHost $VirtualHost -DirectiveName $DirectiveName)
            $DirectivesFound.AddRange($DirectivesInVirtualHosts)

            # If the Directive is not found in the Virtual Host, set the FoundCount to 0 and move on.
            foreach ($found in $DirectivesInVirtualHosts) {
                if ($found.Status -eq "Not Found") {
                    $FoundCount = 0
                    break
                }

                $FoundCount++
            }
        }

        # If we haven't found anything in the Virtual Host, try to find it in the global config.
        if ($FoundCount -le 0) {
            # If nothing is found, check the config files ommiting Vhost blocks.
            $DirectivesInGlobalConfig = [System.Collections.ArrayList]@(Get-ApacheDirectiveFromGlobalConfig -ApacheInstance $ApacheInstance -DirectiveName $DirectiveName)
            $DirectivesFound.AddRange($DirectivesInGlobalConfig)
        }
    }

    return $DirectivesFound
}

function Get-ApacheDirectiveFromBlock {
    param (
        [Parameter(Mandatory)]
        [psobject] $ApacheInstance,
        [Parameter(Mandatory)]
        [AllowNull()]
        [psobject] $VirtualHost,
        [Parameter(Mandatory)]
        [string] $BlockStart,
        [Parameter(Mandatory)]
        [string] $BlockEnd,
        [Parameter(Mandatory)]
        [string] $DirectivePattern
    )

    $DirectivesFound = [System.Collections.ArrayList]@()
    if ($null -eq $VirtualHost) {
        # This will always be a server check.
        $DirectivesInGlobalConfig = [System.Collections.ArrayList]@(Get-ApacheBlockFromGlobalConfig -ApacheInstance $ApacheInstance -BlockStart $BlockStart -BlockEnd $BlockEnd -DirectiveName $DirectivePattern)
        $DirectivesFound.AddRange($DirectivesInGlobalConfig)
        foreach ($vhost in $ApacheInstance.VirtualHosts) {
            if ($vhost.Index -eq -1) {
                continue
            }

            $DirectivesInVirtualHosts = [System.Collections.ArrayList]@(Get-ApacheBlockFromVirtualBlock -VirtualHost $vhost -BlockStart $BlockStart -BlockEnd $BlockEnd -DirectiveName $DirectivePattern)
            $DirectivesFound.AddRange($DirectivesInVirtualHosts)
        }
    }
    else {
        $FoundCount = 0

        # This will execute if you pass in a Virtual Host to the funciton.
        # Check the Virtual Host for the Directive first.
        if ($VirtualHost.Index -ne -1) {
            $DirectivesInVirtualHosts = [System.Collections.ArrayList]@(Get-ApacheBlockFromVirtualBlock -VirtualHost $VirtualHost -BlockStart $BlockStart -BlockEnd $BlockEnd -DirectiveName $DirectivePattern)
            $DirectivesFound.AddRange($DirectivesInVirtualHosts)

            # If the Directive is not found in the Virtual Host, set the FoundCount to 0 and move on.
            foreach ($found in $DirectivesInVirtualHosts) {
                if ($found.Status -eq "Not Found") {
                    $FoundCount = 0
                    break
                }

                $FoundCount++
            }
        }

        # If we haven't found anyything in the Virtual Host, try to find it in the global config.
        if ($FoundCount -le 0) {
            # If nothing is found, check the config files ommiting Vhost blocks.
            $DirectivesInGlobalConfig = [System.Collections.ArrayList]@(Get-ApacheBlockFromGlobalConfig -ApacheInstance $ApacheInstance -BlockStart $BlockStart -BlockEnd $BlockEnd -DirectiveName $DirectivePattern)
            $DirectivesFound.AddRange($DirectivesInGlobalConfig)
        }
    }

    return $DirectivesFound
}

function Get-ApacheFormattedOutput {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [psobject[]] $FoundValues,
        [Parameter(Mandatory)]
        [string] $ExpectedValue,
        [Parameter(Mandatory = $false)]
        [bool] $IsInGlobalConfig,
        [Parameter(Mandatory = $false)]
        [bool] $IsInAllVirtualHosts
    )

    Process {
        $Output = "" # Start with a clean slate.
        foreach ($FoundValue in $FoundValues) {
            #This is a Directive
            if ($FoundValue.Status -eq "Found") {
                $Output += "Directive:`t`t`t$($FoundValue.Name)" | Out-String
                $Output += "Expected Value:`t$($ExpectedValue)" | Out-String
                $Output += "Detected Value:`t$($FoundValue.ConfigFileLine)" | Out-String
                $Output += "In File:`t`t`t$($FoundValue.ConfigFile)" | Out-String
                $Output += "On Line:`t`t`t$($FoundValue.LineNumber)" | Out-String

                if ($null -ne $FoundValue.VirtualHost) {
                    $Output += "Config Level:`t`tVirtual Host" | Out-String
                    $SiteName = $FoundValue.VirtualHost.SiteName + ":" + $FoundValue.VirtualHost.SitePort
                    $Output += "Site Name:`t`t$SiteName" | Out-String
                }
                else {
                    $Output += "Config Level:`t`tGlobal" | Out-String
                }
                $Output += "" | Out-String
            }
            #This is a Directive
            elseif ($FoundValue.Status -eq "Not Found") {
                if (((($null -eq $FoundValue.VirtualHost) -and ($IsInAllVirtualHosts -ne "$false")) -or (($null -ne $FoundValue.VirtualHost) -and ($IsInGlobalConfig -ne "$false")))) {

                    $Output += "Directive:`t`t`t$($FoundValue.Name)" | Out-String
                    $Output += "Expected Value:`t$($ExpectedValue)" | Out-String
                    $Output += "Detected Value:`t$($FoundValue.ConfigFileLine)" | Out-String

                    if ($null -ne $FoundValue.VirtualHost) {
                        $Output += "Config Level:`t`tVirtual Host" | Out-String
                        $SiteName = $FoundValue.VirtualHost.SiteName + ":" + $FoundValue.VirtualHost.SitePort
                        $Output += "Site Name:`t`t$SiteName" | Out-String
                    }
                    else {
                        $Output += "Config Level:`t`tGlobal" | Out-String
                    }
                    $Output += "" | Out-String
                }
            }
            else {
                #This is a Module (Should be  'Enabled' or 'Disabled')
                $Output += "Module:`t`t`t$($FoundValue.Name)" | Out-String
                $Output += "Expected Status:`t$($ExpectedValue)" | Out-String
                $Output += "Detected Status:`t$($FoundValue.Status)" | Out-String
                if ($FoundValue.ConfigFileLine -ne "Not Found") {
                    $Output += "Config File Line:`t$($FoundValue.ConfigFileLine)" | Out-String
                    $Output += "In File:`t`t`t$($FoundValue.ConfigFile)" | Out-String
                    $Output += "On Line:`t`t`t$($FoundValue.LineNumber)" | Out-String
                }
                $Output += "" | Out-String
            }
        }
        return $Output
    }
}

function Test-ApacheDirectiveInAllVirtualHosts {
    param (
        [Parameter(Mandatory)]
        [psobject] $ApacheInstance,
        [Parameter(Mandatory)]
        [psobject[]] $ApacheDirectives
    )

    $VhostCount = 0
    $VirtualHostArray = [System.Collections.ArrayList]@()
    $ApacheVhostsCount = ($ApacheInstance.VirtualHosts | Measure-Object).Count - 1 # -1 to exclude the global config.

    if ($ApacheVhostsCount -eq 0) {
        return $false
    }

    foreach ($directive in $ApacheDirectives) {
        if (($null -eq $directive.VirtualHost) -or ($directive.Status -eq "Not Found")) {
            continue
        }

        $SiteName = $directive.VirtualHost.SiteName + ":" + $directive.VirtualHost.SitePort

        if ($VirtualHostArray.Contains($SiteName)) {
            continue
        }

        $VhostCount++
        [void]$VirtualHostArray.Add($SiteName)
    }

    return ($VhostCount -eq $ApacheVhostsCount)
}

function Test-ApacheDirectiveInGlobal {
    param (
        [Parameter(Mandatory)]
        [psobject[]] $ApacheDirectives
    )

    foreach ($directive in $ApacheDirectives) {
        if ($null -eq $directive.VirtualHost) {
            return ($directive.Status -eq "Found")
        }
    }

    return $false
}

function Get-ApacheLogDirs {
    param (
        [Parameter(Mandatory)]
        [psobject] $ApacheInstance
    )

    $LogDirs = [System.Collections.ArrayList]@()
    $Null = Get-ChildItem -Path $ApacheInstance.HttpdRootPath -Directory | ForEach-Object {
        if ($_.Name -like "log*") {
            $LogDirs.Add($_.FullName)
        }
    }

    $LogLine = & "$($ApacheInstance.ExecutablePath)" -S

    # Assume we are dealing with a path.
    $PathPattern = '(?=[a-z|A-Z]\:)'
    $ErrorLogLine = (((($LogLine | Select-String -Pattern "ErrorLog:") -replace '"') -replace ".*ErrorLog\:\s+") -replace "Program Files", "PROGRA~1") -replace "Program Files \(x86\)", "PROGRA~2"
    $ErrorLogSplit = $ErrorLogLine -split $PathPattern

    $PipePattern = "\||\|\$"
    # Test for a pipe. It will look something like this "|C:\Some\Path\Here"  or "|$\Some\Path\Here"
    # If we split on white space, test the first path to see if it's a pipe.
    $IsPipePattern = [bool]($ErrorLogSplit[0] | Select-String -Pattern $PipePattern -Quiet)
    if ($IsPipePattern) {
        # At this point I feel like the best we can do is loop over the split values.
        # Skip the first value because we know it's the path to the piped executable.
        for ($i = 2; $i -le ($ErrorLogSplit | Measure-Object).Count; $i++) {
            if ([string]::IsNullOrEmpty($ErrorLogSplit[$i])) {
                continue
            }

            # Resolve the path to get rid of stuff like "PROGRA~1" for comparison.
            $SystemErrorLog = [System.IO.Path]::GetFullPath((Split-Path -Path $ErrorLogSplit[$i]))
            if (Test-Path -Path $SystemErrorLog -PathType Container) {
                if (-not ($LogDirs.Contains($SystemErrorLog))) {
                    [void]$LogDirs.Add($SystemErrorLog)
                }
            }
        }
    }
    else {
        $SystemErrorLog = [System.IO.Path]::GetFullPath((Split-Path -Path $ErrorLogLine))
        if (Test-Path -Path $SystemErrorLog -PathType Container) {
            if (-not ($LogDirs.Contains($SystemErrorLog))) {
                [void]$LogDirs.Add($SystemErrorLog)
            }
        }
    }

    return $LogDirs
}

############################################################
## Apache Functions                                        #
############################################################

############################################################
## Postgres Functions                                      #
############################################################
function Test-IsPostgresInstalled {
    $STIGRequired = $false
    Try {
        if ($IsLinux) {
            $IsPostgresInstalled = (ps f -opid','cmd -C 'postgres,postmaster' --no-headers)
			if($IsPostgresInstalled){
				$STIGRequired = $true
			}
		}
		else {
			$IsPostgresInstalled = (Get-InstalledSoftware | Where DisplayName -Like "Postgres*")
			if($IsPostgresInstalled){
				$STIGRequired = $true
			}
		}
	}

	Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

############################################################
## Postgres Functions                                      #
############################################################

############################################################
## McAfee ENS 10x Functions                                #
############################################################

function Get-McAfeeOptDirs {
    return @(pgrep -f mfe | xargs ps -h -o cmd | Sort-Object -u | ForEach-Object { Split-Path -Path $_ })
}

function Test-IsMcAfeeInstalled {
    $STIGRequired = $false
    Try {
        if ($IsLinux) {
            $IsMcAfeeInstalled = ((Get-McAfeeOptDirs | Measure-Object).Count -ge 1)
            $IsENSInstalled = (((find /opt -type d -name ens) | Measure-Object).Count -ge 1)
            if ($IsMcAfeeInstalled -eq $true -and $IsENSInstalled -eq $true) {
                $Parameters = "-i"
                $Exec = (find /opt -type f -name cmdagent)
                $AgentModeString = (Invoke-Expression "$($Exec) $($Parameters)") | Select-String -Pattern AgentMode -Raw
                if ($null -ne $AgentModeString -and $AgentModeString -ne "") {
                    $AgentMode = ($AgentModeString.Split(":")[1]).Trim()
                    if ($AgentMode -eq "0") {
                        $STIGRequired = $true
                    }
                }
            }
        }
        else {
            $RegistryPath = "HKLM:\SOFTWARE\McAfee\Endpoint\Common"
            $RegistryValueName = "ProductVersion"
            $IsVersionTenPlus = ((Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName).Value -Like "10.*")
            if ($IsVersionTenPlus -eq $true) {
                $RegistryPath = "HKLM:\SOFTWARE\WOW6432Node\McAfee\Agent"
                $RegistryValueName = "AgentMode"
                $AgentMode = (Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName).Value
                if ($null -eq $AgentMode -or $AgentMode -eq "(NotFound)") {
                    $STIGRequired = $true
                }
                else {
                    $IsAgentModeZero = ($AgentMode -eq "0")
                    if ($IsAgentModeZero -eq $true) {
                        $STIGRequired = $true
                    }
                }
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

############################################################
## McAfee ENS 10x Functions                                #
############################################################

# SIG # Begin signature block
# MIIL+QYJKoZIhvcNAQcCoIIL6jCCC+YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDBID4ao3n4OYvx
# H4Z+DULQJogQ4tZAjEAETAE9afdsSKCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAJ/5WamkBfOA6QLV9tiOnJNDL/32Jv
# 0wcnqhCKExftgDANBgkqhkiG9w0BAQEFAASCAQAKCNZDJkQAGk9G4/e4QmRxGl3O
# kVACkIz4Od6gMeApZmyGE+v4QBimApHVWxA8/Vm7JDeb/kJmEKuUoWe2GmtOGZ9O
# TpOULnEWPEIZojIcdGQltRvplGxbd3A/ewCAQxYC3bVkqHFArSky/75IB87yxZ2P
# C0QhqwsnsieHlVJl2mC4lA2n0IkSQt0ZwzXdCfVn0V5EUiGEKdvYSslmq5VL/yvM
# jwKD1hOyIUGiRkSzMrJ/3HbKu7RwOwaj9rZhPxflWhHqhhcVVHIGqqZOP1BzGgTw
# 9wUJbLALIsnPjoazN/OrpAzlvz1ReKHWPNNqqEyLuQNoKiFxigFjPdP4P3Iz
# SIG # End signature block
