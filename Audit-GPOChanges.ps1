<#
.SYNOPSIS
    Audits Group Policy configuration and link changes across all domain controllers.

.DESCRIPTION
    Captures:
      - GPO setting changes (5136 on GPO objects)
      - GPO creation/deletion (5137/5141)
      - GPO linked/unlinked from OUs, domains, and sites (gPLink)
      - Link enabled/disabled (gPLink option bit 0x1)
      - Link enforced/unenforced (gPLink option bit 0x2)
      - GPO link sequence/order changes
      - Block Inheritance enabled/disabled (gPOptions)

    GPO configuration changes are compared against an XML Get-GPOReport baseline.
    The CSV attempts to show the actual policy setting that changed, including
    friendly names for User Rights Assignment settings such as:

        Computer Configuration > Windows Settings > Security Settings >
        Local Policies > User Rights Assignment > Log on as a batch job

    Security Event RecordId state is maintained separately for every DC.

.PARAMETER InitializeBaseline
    Creates/refreshes the Get-GPOReport XML baseline for every current GPO and exits.

.PARAMETER InitialLookbackHours
    Number of hours to query when a DC does not yet have a state file.

.EXAMPLE
    .\Audit-GPOChanges-v2.ps1 -InitializeBaseline -Verbose

.EXAMPLE
    .\Audit-GPOChanges-v2.ps1 -Verbose

.NOTES
    Windows PowerShell 5.1 compatible.

    Requires:
      - ActiveDirectory module
      - GroupPolicy module
      - Permission to read the Security log on each DC
      - Directory Service Changes auditing + appropriate SACLs

    IMPORTANT:
      Auditing CN=Policies alone is not sufficient for GPO link auditing.
      gPLink/gPOptions changes occur on the OU/domain/site object being linked.
#>

[CmdletBinding()]
param (
    [switch]$InitializeBaseline,
    [ValidateRange(1,168)]
    [int]$InitialLookbackHours = 2
)

# ============================================================================
# CONFIGURATION
# ============================================================================

$RootPath     = 'C:\ProgramData\GPOAudit'
$StatePath    = Join-Path $RootPath 'State'
$SnapshotPath = Join-Path $RootPath 'Snapshots'
$PendingPath  = Join-Path $RootPath 'Pending'
$CsvPath      = Join-Path $RootPath 'GPOChanges.csv'

# ============================================================================
# FRIENDLY NAMES
# ============================================================================

$UserRightNames = @{
    'SeNetworkLogonRight'                    = 'Access this computer from the network'
    'SeMachineAccountPrivilege'              = 'Add workstations to domain'
    'SeTcbPrivilege'                         = 'Act as part of the operating system'
    'SeIncreaseQuotaPrivilege'               = 'Adjust memory quotas for a process'
    'SeInteractiveLogonRight'                = 'Allow log on locally'
    'SeRemoteInteractiveLogonRight'          = 'Allow log on through Remote Desktop Services'
    'SeBackupPrivilege'                      = 'Back up files and directories'
    'SeChangeNotifyPrivilege'                = 'Bypass traverse checking'
    'SeSystemtimePrivilege'                  = 'Change the system time'
    'SeTimeZonePrivilege'                    = 'Change the time zone'
    'SeCreatePagefilePrivilege'              = 'Create a pagefile'
    'SeCreateTokenPrivilege'                 = 'Create a token object'
    'SeCreateGlobalPrivilege'                = 'Create global objects'
    'SeCreatePermanentPrivilege'             = 'Create permanent shared objects'
    'SeCreateSymbolicLinkPrivilege'          = 'Create symbolic links'
    'SeDebugPrivilege'                       = 'Debug programs'
    'SeDenyNetworkLogonRight'                = 'Deny access to this computer from the network'
    'SeDenyBatchLogonRight'                  = 'Deny log on as a batch job'
    'SeDenyServiceLogonRight'                = 'Deny log on as a service'
    'SeDenyInteractiveLogonRight'            = 'Deny log on locally'
    'SeDenyRemoteInteractiveLogonRight'      = 'Deny log on through Remote Desktop Services'
    'SeEnableDelegationPrivilege'            = 'Enable computer and user accounts to be trusted for delegation'
    'SeRemoteShutdownPrivilege'              = 'Force shutdown from a remote system'
    'SeAuditPrivilege'                       = 'Generate security audits'
    'SeImpersonatePrivilege'                 = 'Impersonate a client after authentication'
    'SeIncreaseBasePriorityPrivilege'        = 'Increase scheduling priority'
    'SeIncreaseWorkingSetPrivilege'          = 'Increase a process working set'
    'SeLoadDriverPrivilege'                  = 'Load and unload device drivers'
    'SeLockMemoryPrivilege'                  = 'Lock pages in memory'
    'SeBatchLogonRight'                      = 'Log on as a batch job'
    'SeServiceLogonRight'                    = 'Log on as a service'
    'SeSecurityPrivilege'                    = 'Manage auditing and security log'
    'SeRelabelPrivilege'                     = 'Modify an object label'
    'SeSystemEnvironmentPrivilege'           = 'Modify firmware environment values'
    'SeManageVolumePrivilege'                = 'Perform volume maintenance tasks'
    'SeProfileSingleProcessPrivilege'        = 'Profile single process'
    'SeSystemProfilePrivilege'               = 'Profile system performance'
    'SeUndockPrivilege'                      = 'Remove computer from docking station'
    'SeAssignPrimaryTokenPrivilege'          = 'Replace a process level token'
    'SeRestorePrivilege'                     = 'Restore files and directories'
    'SeShutdownPrivilege'                    = 'Shut down the system'
    'SeSyncAgentPrivilege'                   = 'Synchronize directory service data'
    'SeTakeOwnershipPrivilege'               = 'Take ownership of files or other objects'
    'SeTrustedCredManAccessPrivilege'        = 'Access Credential Manager as a trusted caller'
    'SeDelegateSessionUserImpersonatePrivilege' = 'Obtain an impersonation token for another user in the same session'
}

$AccountPolicyNames = @{
    'MinimumPasswordLength' = 'Minimum password length'
    'PasswordHistorySize'   = 'Enforce password history'
    'PasswordComplexity'    = 'Password must meet complexity requirements'
    'MaximumPasswordAge'    = 'Maximum password age'
    'MinimumPasswordAge'    = 'Minimum password age'
    'ClearTextPassword'     = 'Store passwords using reversible encryption'
    'LockoutBadCount'       = 'Account lockout threshold'
    'LockoutDuration'       = 'Account lockout duration'
    'ResetLockoutCount'     = 'Reset account lockout counter after'
}

# ============================================================================
# MODULES / DIRECTORIES / DOMAIN
# ============================================================================

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module GroupPolicy -ErrorAction Stop
}
catch {
    Write-Error "Unable to load ActiveDirectory/GroupPolicy modules: $($_.Exception.Message)"
    exit 1
}

foreach ($Path in @($RootPath,$StatePath,$SnapshotPath,$PendingPath)) {
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

try {
    $Domain    = Get-ADDomain -ErrorAction Stop
    $DomainDNS = $Domain.DNSRoot
    $DomainDN  = $Domain.DistinguishedName
    $PDC       = $Domain.PDCEmulator
    $DCs       = @(Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName)
}
catch {
    Write-Error "Unable to retrieve domain information: $($_.Exception.Message)"
    exit 1
}

Write-Verbose "Domain: $DomainDNS"
Write-Verbose "PDC: $PDC"
Write-Verbose "DCs: $($DCs -join ', ')"

# Caches
$GPONameCache    = @{}
$TargetInfoCache = @{}

# ============================================================================
# GENERAL HELPERS
# ============================================================================

function Convert-ToSingleLine {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    return (($Value -replace '\s+', ' ').Trim())
}

function Get-StateFile {
    param([Parameter(Mandatory)][string]$DomainController)

    $SafeName = $DomainController -replace '[^a-zA-Z0-9._-]', '_'
    Join-Path $StatePath "$SafeName.state"
}

function Get-StateValue {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path $Path)) {
        return [pscustomobject]@{ Exists = $false; Value = [long]0 }
    }

    try {
        $Content = (Get-Content -Path $Path -Raw -ErrorAction Stop).Trim()
        [long]$RecordID = $Content
        return [pscustomobject]@{ Exists = $true; Value = $RecordID }
    }
    catch {
        Write-Warning "Invalid state file '$Path'. Initial lookback will be used."
        return [pscustomobject]@{ Exists = $false; Value = [long]0 }
    }
}

function Set-StateValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][long]$RecordID
    )

    Set-Content -Path $Path -Value $RecordID -Encoding ASCII -Force -ErrorAction Stop
    Write-Verbose "State updated: $Path = $RecordID"
}

function Get-EventDataHashtable {
    param([Parameter(Mandatory)][xml]$Xml)

    $Data = @{}
    $Nodes = @($Xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']"))

    foreach ($Node in $Nodes) {
        if ($null -eq $Node) { continue }
        $Name = $Node.GetAttribute('Name')
        if (-not [string]::IsNullOrWhiteSpace($Name) -and -not $Data.ContainsKey($Name)) {
            $Data[$Name] = $Node.InnerText
        }
    }

    return $Data
}

function Convert-OperationType {
    param([AllowNull()][string]$Operation)

    switch ($Operation) {
        '%%14674' { 'Value Added' }
        '%%14675' { 'Value Deleted' }
        default   { $Operation }
    }
}

function Get-SnapshotFile {
    param([Parameter(Mandatory)][string]$Guid)

    $CleanGuid = $Guid.Trim('{}')
    Join-Path $SnapshotPath "$CleanGuid.xml"
}

function Get-GPONameFromSnapshot {
    param([Parameter(Mandatory)][string]$Guid)

    $SnapshotFile = Get-SnapshotFile -Guid $Guid
    if (-not (Test-Path $SnapshotFile)) { return $null }

    try {
        [xml]$Snapshot = Get-Content -Path $SnapshotFile -Raw -ErrorAction Stop
        $NameNode = $Snapshot.SelectSingleNode("/*[local-name()='GPO']/*[local-name()='Name']")
        if ($NameNode) { return (Convert-ToSingleLine $NameNode.InnerText) }
    }
    catch {}

    return $null
}

function Resolve-GPOName {
    param(
        [Parameter(Mandatory)][string]$Guid,
        [string]$Server = $PDC
    )

    $CleanGuid = $Guid.Trim('{}').ToUpperInvariant()
    if ($GPONameCache.ContainsKey($CleanGuid)) { return $GPONameCache[$CleanGuid] }

    try {
        $Name = (Get-GPO -Guid $CleanGuid -Domain $DomainDNS -Server $Server -ErrorAction Stop).DisplayName
    }
    catch {
        $Name = Get-GPONameFromSnapshot -Guid $CleanGuid
        if (-not $Name) { $Name = '<Deleted or Unable to Resolve>' }
    }

    $GPONameCache[$CleanGuid] = $Name
    return $Name
}

function Resolve-TargetInfo {
    param([Parameter(Mandatory)][string]$DistinguishedName)

    if ($TargetInfoCache.ContainsKey($DistinguishedName)) {
        return $TargetInfoCache[$DistinguishedName]
    }

    $TargetName = $DistinguishedName
    $TargetType = 'AD Container'

    try {
        $Obj = Get-ADObject -Identity $DistinguishedName -Properties objectClass -Server $PDC -ErrorAction Stop
        $TargetName = $Obj.Name

        $Classes = @($Obj.ObjectClass)
        if ($Classes -contains 'organizationalUnit') { $TargetType = 'OU' }
        elseif ($Classes -contains 'domainDNS')       { $TargetType = 'Domain' }
        elseif ($Classes -contains 'site')            { $TargetType = 'Site' }
        elseif ($DistinguishedName -eq $DomainDN)     { $TargetType = 'Domain' }
    }
    catch {
        if ($DistinguishedName -match '(?i)^OU=([^,]+),') {
            $TargetName = $Matches[1]
            $TargetType = 'OU'
        }
        elseif ($DistinguishedName -eq $DomainDN) {
            $TargetName = $DomainDNS
            $TargetType = 'Domain'
        }
        elseif ($DistinguishedName -match '(?i)^CN=([^,]+),CN=Sites,') {
            $TargetName = $Matches[1]
            $TargetType = 'Site'
        }
    }

    $Result = [pscustomobject]@{
        Name = $TargetName
        Type = $TargetType
        DN   = $DistinguishedName
    }

    $TargetInfoCache[$DistinguishedName] = $Result
    return $Result
}

# ============================================================================
# GPO LINK DECODING
# ============================================================================

function Convert-GPLinkString {
    param([AllowNull()][string]$Value)

    $Results = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Results }

    $RegexMatches = [regex]::Matches(
        $Value,
        '\[LDAP://(?<DN>.*?);(?<Options>\d+)\]',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    $Position = 0

    foreach ($Match in $RegexMatches) {
        $Position++
        $GpoDN = $Match.Groups['DN'].Value
        [int]$Options = $Match.Groups['Options'].Value

        $Guid = $null
        if ($GpoDN -match '(?i)CN=\{(?<GUID>[0-9A-F-]{36})\}') {
            $Guid = $Matches['GUID'].ToUpperInvariant()
        }

        $Results.Add([pscustomobject]@{
            Guid             = $Guid
            GpoDN            = $GpoDN
            Options          = $Options
            Enabled          = (($Options -band 1) -eq 0)
            Enforced         = (($Options -band 2) -ne 0)
            SequencePosition = $Position
        })
    }

    return $Results
}

function Compare-GPLinkChange {
    param(
        [Parameter(Mandatory)][object[]]$Events,
        [Parameter(Mandatory)][string]$TargetDN
    )

    $Output = New-Object System.Collections.Generic.List[object]
    $Target = Resolve-TargetInfo -DistinguishedName $TargetDN

    $OldValue = @(
        $Events |
        Where-Object { $_.Operation -eq 'Value Deleted' } |
        Sort-Object EventRecordID |
        Select-Object -Last 1
    ).Value

    $NewValue = @(
        $Events |
        Where-Object { $_.Operation -eq 'Value Added' } |
        Sort-Object EventRecordID |
        Select-Object -Last 1
    ).Value

    if ($OldValue -is [array]) { $OldValue = $OldValue[-1] }
    if ($NewValue -is [array]) { $NewValue = $NewValue[-1] }

    $OldLinks = @(Convert-GPLinkString -Value $OldValue)
    $NewLinks = @(Convert-GPLinkString -Value $NewValue)

    $OldMap = @{}
    foreach ($Link in $OldLinks) {
        if ($Link.Guid) { $OldMap[$Link.Guid] = $Link }
    }

    $NewMap = @{}
    foreach ($Link in $NewLinks) {
        if ($Link.Guid) { $NewMap[$Link.Guid] = $Link }
    }

    $AllGuids = @($OldMap.Keys) + @($NewMap.Keys) | Sort-Object -Unique

    foreach ($Guid in $AllGuids) {
        $OldExists = $OldMap.ContainsKey($Guid)
        $NewExists = $NewMap.ContainsKey($Guid)
        $GPOName   = Resolve-GPOName -Guid $Guid

        if (-not $OldExists -and $NewExists) {
            $Link = $NewMap[$Guid]
            $StateText = if ($Link.Enabled) { 'Enabled' } else { 'Disabled' }
            $EnforcedText = if ($Link.Enforced) { 'Enforced' } else { 'Not enforced' }

            $Output.Add([pscustomobject]@{
                Action         = 'Linked'
                GPOName        = $GPOName
                GPOGuid        = $Guid
                TargetType     = $Target.Type
                TargetName     = $Target.Name
                TargetDN       = $Target.DN
                ChangedSetting = "GPO link to $($Target.Type) '$($Target.Name)'"
                PreviousValue  = 'Not linked'
                NewValue       = "Linked ($StateText, $EnforcedText)"
            })
            continue
        }

        if ($OldExists -and -not $NewExists) {
            $Link = $OldMap[$Guid]
            $StateText = if ($Link.Enabled) { 'Enabled' } else { 'Disabled' }
            $EnforcedText = if ($Link.Enforced) { 'Enforced' } else { 'Not enforced' }

            $Output.Add([pscustomobject]@{
                Action         = 'Unlinked'
                GPOName        = $GPOName
                GPOGuid        = $Guid
                TargetType     = $Target.Type
                TargetName     = $Target.Name
                TargetDN       = $Target.DN
                ChangedSetting = "GPO link to $($Target.Type) '$($Target.Name)'"
                PreviousValue  = "Linked ($StateText, $EnforcedText)"
                NewValue       = 'Not linked'
            })
            continue
        }

        $Old = $OldMap[$Guid]
        $New = $NewMap[$Guid]

        if ($Old.Enabled -ne $New.Enabled) {
            $Action = if ($New.Enabled) { 'Link Enabled' } else { 'Link Disabled' }
            $Output.Add([pscustomobject]@{
                Action         = $Action
                GPOName        = $GPOName
                GPOGuid        = $Guid
                TargetType     = $Target.Type
                TargetName     = $Target.Name
                TargetDN       = $Target.DN
                ChangedSetting = "GPO link enabled state on $($Target.Type) '$($Target.Name)'"
                PreviousValue  = [string]$Old.Enabled
                NewValue       = [string]$New.Enabled
            })
        }

        if ($Old.Enforced -ne $New.Enforced) {
            $Action = if ($New.Enforced) { 'Enforced' } else { 'Unenforced' }
            $Output.Add([pscustomobject]@{
                Action         = $Action
                GPOName        = $GPOName
                GPOGuid        = $Guid
                TargetType     = $Target.Type
                TargetName     = $Target.Name
                TargetDN       = $Target.DN
                ChangedSetting = "GPO link enforcement on $($Target.Type) '$($Target.Name)'"
                PreviousValue  = [string]$Old.Enforced
                NewValue       = [string]$New.Enforced
            })
        }

        if ($Old.SequencePosition -ne $New.SequencePosition) {
            $Output.Add([pscustomobject]@{
                Action         = 'Link Order Changed'
                GPOName        = $GPOName
                GPOGuid        = $Guid
                TargetType     = $Target.Type
                TargetName     = $Target.Name
                TargetDN       = $Target.DN
                ChangedSetting = "GPO link sequence on $($Target.Type) '$($Target.Name)'"
                PreviousValue  = "Sequence position $($Old.SequencePosition)"
                NewValue       = "Sequence position $($New.SequencePosition)"
            })
        }
    }

    return $Output
}

function Compare-GPOptionsChange {
    param(
        [Parameter(Mandatory)][object[]]$Events,
        [Parameter(Mandatory)][string]$TargetDN
    )

    $Target = Resolve-TargetInfo -DistinguishedName $TargetDN

    $OldRaw = @(
        $Events |
        Where-Object { $_.Operation -eq 'Value Deleted' } |
        Sort-Object EventRecordID |
        Select-Object -Last 1
    ).Value

    $NewRaw = @(
        $Events |
        Where-Object { $_.Operation -eq 'Value Added' } |
        Sort-Object EventRecordID |
        Select-Object -Last 1
    ).Value

    if ($OldRaw -is [array]) { $OldRaw = $OldRaw[-1] }
    if ($NewRaw -is [array]) { $NewRaw = $NewRaw[-1] }

    [int]$Old = 0
    [int]$New = 0
    if (-not [string]::IsNullOrWhiteSpace([string]$OldRaw)) { [void][int]::TryParse([string]$OldRaw,[ref]$Old) }
    if (-not [string]::IsNullOrWhiteSpace([string]$NewRaw)) { [void][int]::TryParse([string]$NewRaw,[ref]$New) }

    if ($Old -eq $New) { return @() }

    $OldBlocked = (($Old -band 1) -ne 0)
    $NewBlocked = (($New -band 1) -ne 0)

    $Action = if ($NewBlocked) { 'Block Inheritance Enabled' } else { 'Block Inheritance Disabled' }

    return @([pscustomobject]@{
        Action         = $Action
        GPOName        = ''
        GPOGuid        = ''
        TargetType     = $Target.Type
        TargetName     = $Target.Name
        TargetDN       = $Target.DN
        ChangedSetting = "Block Inheritance on $($Target.Type) '$($Target.Name)'"
        PreviousValue  = [string]$OldBlocked
        NewValue       = [string]$NewBlocked
    })
}

# ============================================================================
# GPO SETTING XML PARSING
# ============================================================================

function Get-DirectChildText {
    param(
        [Parameter(Mandatory)][System.Xml.XmlNode]$Node,
        [Parameter(Mandatory)][string]$Name
    )

    $Child = $Node.SelectSingleNode("./*[local-name()='$Name']")
    if ($Child) { return (Convert-ToSingleLine $Child.InnerText) }
    return ''
}

function Get-FriendlySettingName {
    param([Parameter(Mandatory)][string]$RawName)

    if ($UserRightNames.ContainsKey($RawName))   { return $UserRightNames[$RawName] }
    if ($AccountPolicyNames.ContainsKey($RawName)) { return $AccountPolicyNames[$RawName] }
    return $RawName
}

function Get-SettingIdentity {
    param([Parameter(Mandatory)][System.Xml.XmlNode]$Node)

    foreach ($Candidate in @('Name','PolicyName','DisplayName','SubcategoryName','ValueName','Key','Path')) {
        $Value = Get-DirectChildText -Node $Node -Name $Candidate
        if ($Value) { return $Value }
    }

    if ($Node.Attributes) {
        foreach ($Candidate in @('name','key','path','valueName')) {
            $Attr = $Node.Attributes[$Candidate]
            if ($Attr -and $Attr.Value) { return (Convert-ToSingleLine $Attr.Value) }
        }
    }

    $Properties = $Node.SelectSingleNode("./*[local-name()='Properties']")
    if ($Properties -and $Properties.Attributes) {
        foreach ($Candidate in @('name','key','path','valueName','serviceName','appName')) {
            $Attr = $Properties.Attributes[$Candidate]
            if ($Attr -and $Attr.Value) { return (Convert-ToSingleLine $Attr.Value) }
        }
    }

    return ''
}

function Get-SettingNodesRecursive {
    param([Parameter(Mandatory)][System.Xml.XmlNode]$Node)

    $Identity = Get-SettingIdentity -Node $Node

    if ($Identity -and $Node.LocalName -notin @('Extension','ExtensionData','GPO','Member')) {
        Write-Output $Node
        return
    }

    foreach ($Child in @($Node.ChildNodes)) {
        if ($Child.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
        if ($Child.LocalName -in @('GPO','Precedence')) { continue }
        Get-SettingNodesRecursive -Node $Child
    }
}

function Test-IsInsideGpoMetadata {
    param(
        [Parameter(Mandatory)][System.Xml.XmlNode]$Leaf,
        [Parameter(Mandatory)][System.Xml.XmlNode]$SettingNode
    )

    $Current = $Leaf.ParentNode
    while ($Current -and $Current -ne $SettingNode) {
        if ($Current.LocalName -eq 'GPO') { return $true }
        $Current = $Current.ParentNode
    }
    return $false
}

function Get-SettingValue {
    param([Parameter(Mandatory)][System.Xml.XmlNode]$Node)

    if ($Node.LocalName -eq 'UserRightsAssignment') {
        $Members = @(
            $Node.SelectNodes("./*[local-name()='Member']/*[local-name()='Name']") |
            ForEach-Object { Convert-ToSingleLine $_.InnerText } |
            Where-Object { $_ } |
            Sort-Object -Unique
        )

        if ($Members.Count -eq 0) { return '<No users or groups assigned>' }
        return ($Members -join '; ')
    }

    $Pairs = New-Object System.Collections.Generic.List[string]
    $Leaves = @($Node.SelectNodes(".//*[not(*) and normalize-space(text()) != '']"))

    foreach ($Leaf in $Leaves) {
        if (Test-IsInsideGpoMetadata -Leaf $Leaf -SettingNode $Node) { continue }
        if ($Leaf.LocalName -in @('Precedence','Identifier','Domain','SID','Type')) { continue }

        # Direct identity fields name the setting; they are not the value.
        if ($Leaf.ParentNode -eq $Node -and $Leaf.LocalName -in @('Name','PolicyName','DisplayName','SubcategoryName','ValueName','Key','Path')) {
            continue
        }

        $Text = Convert-ToSingleLine $Leaf.InnerText
        if (-not $Text) { continue }

        $Label = $Leaf.LocalName
        if ($Leaf.LocalName -eq 'Name' -and $Leaf.ParentNode -ne $Node) {
            $Label = $Leaf.ParentNode.LocalName
        }

        $Pairs.Add("$Label=$Text")
    }

    if ($Pairs.Count -eq 0 -and $Node.Attributes) {
        foreach ($Attr in @($Node.Attributes)) {
            if ($Attr.Name -match '^xmlns') { continue }
            if ($Attr.LocalName -eq 'type') { continue }
            if ($Attr.Value) { $Pairs.Add("$($Attr.LocalName)=$($Attr.Value)") }
        }
    }

    if ($Pairs.Count -eq 0) { return '<Configured>' }
    return (@($Pairs | Sort-Object -Unique) -join '; ')
}

function Get-SettingPath {
    param(
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][System.Xml.XmlNode]$Node,
        [Parameter(Mandatory)][string]$FriendlyName
    )

    $ScopeLabel = if ($Scope -eq 'Computer') { 'Computer Configuration' } else { 'User Configuration' }

    if ($Node.LocalName -eq 'UserRightsAssignment') {
        return "$ScopeLabel > Windows Settings > Security Settings > Local Policies > User Rights Assignment > $FriendlyName"
    }

    if ($Node.LocalName -eq 'SecurityOptions') {
        return "$ScopeLabel > Windows Settings > Security Settings > Local Policies > Security Options > $FriendlyName"
    }

    if ($Node.LocalName -eq 'Account') {
        $Type = Get-DirectChildText -Node $Node -Name 'Type'
        if ($Type -match '(?i)Password') {
            return "$ScopeLabel > Windows Settings > Security Settings > Account Policies > Password Policy > $FriendlyName"
        }
        if ($Type -match '(?i)Lockout') {
            return "$ScopeLabel > Windows Settings > Security Settings > Account Policies > Account Lockout Policy > $FriendlyName"
        }
        return "$ScopeLabel > Windows Settings > Security Settings > Account Policies > $FriendlyName"
    }

    if ($Category -match '(?i)Administrative Templates') {
        return "$ScopeLabel > Administrative Templates > $FriendlyName"
    }

    if ($Category -match '(?i)Security') {
        return "$ScopeLabel > Windows Settings > Security Settings > $($Node.LocalName) > $FriendlyName"
    }

    if ([string]::IsNullOrWhiteSpace($Category)) {
        return "$ScopeLabel > $($Node.LocalName) > $FriendlyName"
    }

    return "$ScopeLabel > $Category > $FriendlyName"
}

function Get-GPOSettingMap {
    param([Parameter(Mandatory)][xml]$GPOXml)

    $Map = @{}

    foreach ($Scope in @('Computer','User')) {
        $ExtensionDataNodes = @(
            $GPOXml.SelectNodes("/*[local-name()='GPO']/*[local-name()='$Scope']/*[local-name()='ExtensionData']")
        )

        foreach ($ExtensionData in $ExtensionDataNodes) {
            $CategoryNode = $ExtensionData.SelectSingleNode("./*[local-name()='Name']")
            $Category = if ($CategoryNode) { Convert-ToSingleLine $CategoryNode.InnerText } else { '' }

            $Extension = $ExtensionData.SelectSingleNode("./*[local-name()='Extension']")
            if (-not $Extension) { continue }

            $SettingNodes = @(Get-SettingNodesRecursive -Node $Extension)

            foreach ($SettingNode in $SettingNodes) {
                $RawName = Get-SettingIdentity -Node $SettingNode
                if (-not $RawName) { continue }

                $FriendlyName = Get-FriendlySettingName -RawName $RawName
                $SettingPath  = Get-SettingPath -Scope $Scope -Category $Category -Node $SettingNode -FriendlyName $FriendlyName
                $Value        = Get-SettingValue -Node $SettingNode

                $BaseKey = "$Scope|$Category|$($SettingNode.LocalName)|$RawName"
                $Key = $BaseKey
                $N = 1
                while ($Map.ContainsKey($Key)) {
                    $N++
                    $Key = "$BaseKey#$N"
                }

                $Map[$Key] = [pscustomobject]@{
                    Setting = $SettingPath
                    Value   = $Value
                    RawName = $RawName
                    Type    = $SettingNode.LocalName
                }
            }
        }
    }

    return $Map
}

function Compare-GPOSettingMap {
    param(
        [Parameter(Mandatory)][hashtable]$Old,
        [Parameter(Mandatory)][hashtable]$New
    )

    $Changes = New-Object System.Collections.Generic.List[object]
    $Keys = @($Old.Keys) + @($New.Keys) | Sort-Object -Unique

    foreach ($Key in $Keys) {
        $OldExists = $Old.ContainsKey($Key)
        $NewExists = $New.ContainsKey($Key)

        if (-not $OldExists -and $NewExists) {
            $Changes.Add([pscustomobject]@{
                Action         = 'Setting Added'
                ChangedSetting = $New[$Key].Setting
                PreviousValue  = '(Not configured)'
                NewValue       = $New[$Key].Value
            })
            continue
        }

        if ($OldExists -and -not $NewExists) {
            $Changes.Add([pscustomobject]@{
                Action         = 'Setting Removed'
                ChangedSetting = $Old[$Key].Setting
                PreviousValue  = $Old[$Key].Value
                NewValue       = '(Not configured)'
            })
            continue
        }

        if ($Old[$Key].Value -ne $New[$Key].Value) {
            $Changes.Add([pscustomobject]@{
                Action         = 'Setting Modified'
                ChangedSetting = $New[$Key].Setting
                PreviousValue  = $Old[$Key].Value
                NewValue       = $New[$Key].Value
            })
        }
    }

    return $Changes
}

function Get-CurrentGPOReport {
    param(
        [Parameter(Mandatory)][string]$Guid,
        [string]$Server = $PDC
    )

    try {
        return Get-GPOReport -Guid $Guid -ReportType Xml -Domain $DomainDNS -Server $Server -ErrorAction Stop
    }
    catch {
        if ($Server -ne $PDC) {
            return Get-GPOReport -Guid $Guid -ReportType Xml -Domain $DomainDNS -Server $PDC -ErrorAction Stop
        }
        throw
    }
}

function Compare-GPOToSnapshot {
    param(
        [Parameter(Mandatory)][string]$Guid,
        [Parameter(Mandatory)][string]$Action,
        [string]$Server = $PDC
    )

    $SnapshotFile = Get-SnapshotFile -Guid $Guid

    if ($Action -eq 'Deleted') {
        return [pscustomobject]@{
            Changes      = @([pscustomobject]@{
                Action         = 'GPO Deleted'
                ChangedSetting = 'Group Policy Object'
                PreviousValue  = Resolve-GPOName -Guid $Guid
                NewValue       = '(Deleted)'
            })
            SnapshotFile = $SnapshotFile
            CurrentXML   = $null
            SaveSnapshot = $false
        }
    }

    try {
        $CurrentXMLText = Get-CurrentGPOReport -Guid $Guid -Server $Server
        [xml]$CurrentXML = $CurrentXMLText
    }
    catch {
        return [pscustomobject]@{
            Changes      = @([pscustomobject]@{
                Action         = 'GPO Modified'
                ChangedSetting = 'GPO configuration changed - current report could not be retrieved'
                PreviousValue  = ''
                NewValue       = $_.Exception.Message
            })
            SnapshotFile = $SnapshotFile
            CurrentXML   = $null
            SaveSnapshot = $false
        }
    }

    if (-not (Test-Path $SnapshotFile)) {
        $Label = if ($Action -eq 'Created') { 'GPO Created' } else { 'Baseline Created' }
        return [pscustomobject]@{
            Changes      = @([pscustomobject]@{
                Action         = $Label
                ChangedSetting = 'Group Policy Object'
                PreviousValue  = '(Did not exist in baseline)'
                NewValue       = Resolve-GPOName -Guid $Guid -Server $Server
            })
            SnapshotFile = $SnapshotFile
            CurrentXML   = $CurrentXMLText
            SaveSnapshot = $true
        }
    }

    try {
        [xml]$PreviousXML = Get-Content -Path $SnapshotFile -Raw -ErrorAction Stop
        $OldMap = Get-GPOSettingMap -GPOXml $PreviousXML
        $NewMap = Get-GPOSettingMap -GPOXml $CurrentXML
        $Changes = @(Compare-GPOSettingMap -Old $OldMap -New $NewMap)
    }
    catch {
        $Changes = @([pscustomobject]@{
            Action         = 'GPO Modified'
            ChangedSetting = 'GPO configuration changed - report comparison failed'
            PreviousValue  = ''
            NewValue       = $_.Exception.Message
        })
    }

    return [pscustomobject]@{
        Changes      = $Changes
        SnapshotFile = $SnapshotFile
        CurrentXML   = $CurrentXMLText
        SaveSnapshot = $true
    }
}

# ============================================================================
# BASELINE
# ============================================================================

function Initialize-GPOBaseline {
    Write-Host ''
    Write-Host 'Initializing GPO configuration baseline...'
    Write-Host ''

    try {
        $GPOs = @(Get-GPO -All -Domain $DomainDNS -Server $PDC -ErrorAction Stop)
    }
    catch {
        Write-Error "Unable to enumerate GPOs: $($_.Exception.Message)"
        return
    }

    $Counter = 0

    foreach ($GPO in $GPOs) {
        $Counter++
        $Guid = $GPO.Id.Guid
        $SnapshotFile = Get-SnapshotFile -Guid $Guid

        Write-Progress -Activity 'Creating GPO baseline' -Status "$Counter of $($GPOs.Count): $($GPO.DisplayName)" -PercentComplete (($Counter / $GPOs.Count) * 100)

        try {
            $XML = Get-GPOReport -Guid $Guid -ReportType Xml -Domain $DomainDNS -Server $PDC -ErrorAction Stop
            Set-Content -Path $SnapshotFile -Value $XML -Encoding UTF8 -Force -ErrorAction Stop
            Write-Verbose "Baseline: $($GPO.DisplayName)"
        }
        catch {
            Write-Warning "Unable to baseline '$($GPO.DisplayName)': $($_.Exception.Message)"
        }
    }

    Write-Progress -Activity 'Creating GPO baseline' -Completed
    Write-Host "Baseline complete. $($GPOs.Count) GPOs processed."
}

# ============================================================================
# CSV PERSISTENCE
# ============================================================================

function Flush-PendingCSV {
    $PendingFiles = @(
        Get-ChildItem -Path $PendingPath -Filter '*.csv' -File -ErrorAction SilentlyContinue |
        Sort-Object CreationTime
    )

    foreach ($PendingFile in $PendingFiles) {
        try {
            $Rows = @(Import-Csv -Path $PendingFile.FullName -ErrorAction Stop)
            if ($Rows.Count -gt 0) {
                $Rows | Export-Csv -Path $CsvPath -NoTypeInformation -Append -Encoding UTF8 -ErrorAction Stop
            }
            Remove-Item -Path $PendingFile.FullName -Force -ErrorAction Stop
            Write-Verbose "Merged pending file: $($PendingFile.Name)"
        }
        catch {
            Write-Warning "Unable to merge pending CSV '$($PendingFile.Name)'. Main CSV may be open."
            break
        }
    }
}

function Write-AuditRows {
    param([object[]]$Rows)

    $Rows = @($Rows)
    if ($Rows.Count -eq 0) { return $true }

    try {
        $Rows | Export-Csv -Path $CsvPath -NoTypeInformation -Append -Encoding UTF8 -ErrorAction Stop
        Write-Verbose "Wrote $($Rows.Count) row(s) to $CsvPath"
        return $true
    }
    catch {
        Write-Warning 'Primary CSV could not be written. It may be open in Excel.'
        $PendingFile = Join-Path $PendingPath "GPOChanges_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').csv"

        try {
            $Rows | Export-Csv -Path $PendingFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-Warning "Audit rows queued to $PendingFile"
            return $true
        }
        catch {
            Write-Error "Unable to write primary or pending CSV: $($_.Exception.Message)"
            return $false
        }
    }
}

# ============================================================================
# BASELINE MODE
# ============================================================================

if ($InitializeBaseline) {
    Initialize-GPOBaseline
    return
}

Flush-PendingCSV

# ============================================================================
# QUERY SECURITY EVENTS FROM EACH DC
# ============================================================================

$RawEvents    = New-Object System.Collections.Generic.List[object]
$StateUpdates = @{}

foreach ($DC in $DCs) {
    Write-Host "Querying $DC..."

    try {
        $LatestSecurityEvent = Get-WinEvent -ComputerName $DC -LogName Security -MaxEvents 1 -ErrorAction Stop
        [long]$UpperRecordID = $LatestSecurityEvent.RecordId
    }
    catch {
        Write-Warning "$DC is unreachable or its Security log cannot be read: $($_.Exception.Message)"
        continue
    }

    $StateFile = Get-StateFile -DomainController $DC
    $State     = Get-StateValue -Path $StateFile
    [long]$LastRecordID = $State.Value
    $HasState = $State.Exists

    if ($HasState -and $LastRecordID -gt $UpperRecordID) {
        Write-Warning "$DC Security log RecordId appears to have reset. Falling back to initial lookback."
        $HasState = $false
        $LastRecordID = 0
    }

    Write-Verbose "$DC LastRecordID=$LastRecordID UpperRecordID=$UpperRecordID"

    try {
        if ($HasState) {
            $XPath = "*[System[((EventID=5136 or EventID=5137 or EventID=5141) and EventRecordID > $LastRecordID and EventRecordID <= $UpperRecordID)]]"
            $Events = @(Get-WinEvent -ComputerName $DC -LogName Security -FilterXPath $XPath -ErrorAction Stop)
        }
        else {
            $StartTime = (Get-Date).AddHours(-$InitialLookbackHours)
            $Events = @(
                Get-WinEvent -ComputerName $DC -FilterHashtable @{
                    LogName   = 'Security'
                    Id        = 5136,5137,5141
                    StartTime = $StartTime
                } -ErrorAction Stop |
                Where-Object { $_.RecordId -le $UpperRecordID }
            )
        }
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' -or $_.Exception.Message -match 'No events were found') {
            $Events = @()
        }
        else {
            Write-Warning "$DC event query failed: $($_.Exception.Message)"
            continue
        }
    }

    Write-Verbose "$DC raw DS-change events: $($Events.Count)"

    $ParseFailed = $false

    foreach ($Event in $Events) {
        try {
            [xml]$Xml = $Event.ToXml()
            $Data = Get-EventDataHashtable -Xml $Xml

            $ObjectDN  = [string]$Data['ObjectDN']
            $Attribute = [string]$Data['AttributeLDAPDisplayName']

            $RecordType = $null
            $GPOGuid = $null

            # GPO object itself under CN=Policies.
            if ($ObjectDN -match '(?i)^CN=\{(?<GPOGUID>[0-9A-F-]{36})\},CN=Policies,CN=System,') {
                $RecordType = 'GPO'
                $GPOGuid = $Matches['GPOGUID'].ToUpperInvariant()
            }
            # GPO link / inheritance metadata lives on the target OU/domain/site object.
            elseif ($Event.Id -eq 5136 -and $Attribute -in @('gPLink','gPOptions')) {
                $RecordType = 'Link'
            }
            else {
                continue
            }

            $Action = switch ($Event.Id) {
                5136 { 'Modified' }
                5137 { 'Created' }
                5141 { 'Deleted' }
                default { 'Unknown' }
            }

            $SubjectDomain = [string]$Data['SubjectDomainName']
            $SubjectUser   = [string]$Data['SubjectUserName']
            $User = if ($SubjectDomain -and $SubjectUser) {
                "$SubjectDomain\$SubjectUser"
            }
            elseif ($SubjectUser) {
                $SubjectUser
            }
            else {
                [string]$Data['SubjectUserSid']
            }

            $RawEvents.Add([pscustomobject]@{
                RecordType       = $RecordType
                TimeCreated      = $Event.TimeCreated
                DomainController = $DC
                User             = $User
                Action           = $Action
                ObjectDN         = $ObjectDN
                GPOGuid          = $GPOGuid
                Attribute        = $Attribute
                Operation        = Convert-OperationType -Operation ([string]$Data['OperationType'])
                Value            = [string]$Data['AttributeValue']
                CorrelationID    = [string]$Data['OpCorrelationID']
                EventID          = [int]$Event.Id
                EventRecordID    = [long]$Event.RecordId
            })
        }
        catch {
            Write-Warning "$DC failed to parse EventRecordID $($Event.RecordId): $($_.Exception.Message)"
            $ParseFailed = $true
            break
        }
    }

    if ($ParseFailed) {
        Write-Warning "$DC state will not be advanced because event parsing failed."
        continue
    }

    $StateUpdates[$DC] = [pscustomobject]@{
        StateFile     = $StateFile
        UpperRecordID = $UpperRecordID
    }
}

Write-Verbose "Relevant GPO/GPO-link events collected: $($RawEvents.Count)"

# ============================================================================
# BUILD FINAL AUDIT ROWS
# ============================================================================

$FinalRows       = New-Object System.Collections.Generic.List[object]
$SnapshotUpdates = @{}

function New-AuditRow {
    param(
        [Parameter(Mandatory)][object]$EventContext,
        [Parameter(Mandatory)][string]$AuditType,
        [Parameter(Mandatory)][string]$Action,
        [string]$GPOName,
        [string]$GPOGuid,
        [string]$TargetType,
        [string]$TargetName,
        [string]$TargetDN,
        [string]$ChangedSetting,
        [string]$PreviousValue,
        [string]$NewValue,
        [string]$ADAttribute,
        [string]$AttributionNote
    )

    $DirectoryAttributeChange = switch ($AuditType) {
        'GPO Link'        { "gPLink changed on $TargetType '$TargetName'" }
        'GPO Inheritance' { "gPOptions changed on $TargetType '$TargetName'" }
        'GPO Setting'     { 'GPO policy content changed' }
        'GPO Lifecycle'   { "GPO object: $Action" }
        'GPO Metadata'    { 'GPO display name changed' }
        default           { '' }
    }

    [pscustomobject]@{
        TimeCreated             = $EventContext.TimeCreated
        DomainController        = $EventContext.DomainController
        User                    = $EventContext.User
        AuditType               = $AuditType
        Action                  = $Action
        GPOName                 = $GPOName
        GPOGuid                 = $GPOGuid
        TargetType              = $TargetType
        TargetName              = $TargetName
        TargetDN                = $TargetDN
        ChangedSetting          = $ChangedSetting
        PreviousValue           = $PreviousValue
        NewValue                = $NewValue
        DirectoryAttributeChange = $DirectoryAttributeChange
        ADAttribute             = $ADAttribute
        CorrelationID           = $EventContext.CorrelationID
        EventIDs                = $EventContext.EventIDs
        EventRecordIDs          = $EventContext.EventRecordIDs
        AttributionNote         = $AttributionNote
    }
}

# ----------------------------------------------------------------------------
# LINK / UNLINK / ENFORCE / UNENFORCE / BLOCK INHERITANCE
# ----------------------------------------------------------------------------

$LinkEvents = @($RawEvents | Where-Object { $_.RecordType -eq 'Link' })

$LinkGroups = @(
    $LinkEvents |
    Group-Object {
        $Corr = $_.CorrelationID
        if ([string]::IsNullOrWhiteSpace($Corr) -or $Corr -eq '-') {
            $Corr = "RID-$($_.EventRecordID)"
        }
        "$($_.DomainController)|$($_.User)|$($_.ObjectDN)|$($_.Attribute)|$Corr"
    }
)

foreach ($Group in $LinkGroups) {
    $Events = @($Group.Group | Sort-Object EventRecordID)
    $First  = $Events[0]

    $Context = [pscustomobject]@{
        TimeCreated      = $First.TimeCreated
        DomainController = $First.DomainController
        User             = $First.User
        CorrelationID    = $First.CorrelationID
        EventIDs         = (@($Events.EventID | Sort-Object -Unique) -join '; ')
        EventRecordIDs   = (@($Events.EventRecordID | Sort-Object) -join '; ')
    }

    if ($First.Attribute -eq 'gPLink') {
        $Changes = @(Compare-GPLinkChange -Events $Events -TargetDN $First.ObjectDN)
        foreach ($Change in $Changes) {
            $FinalRows.Add((New-AuditRow -EventContext $Context -AuditType 'GPO Link' -Action $Change.Action -GPOName $Change.GPOName -GPOGuid $Change.GPOGuid -TargetType $Change.TargetType -TargetName $Change.TargetName -TargetDN $Change.TargetDN -ChangedSetting $Change.ChangedSetting -PreviousValue $Change.PreviousValue -NewValue $Change.NewValue -ADAttribute 'gPLink' -AttributionNote ''))
        }
    }
    elseif ($First.Attribute -eq 'gPOptions') {
        $Changes = @(Compare-GPOptionsChange -Events $Events -TargetDN $First.ObjectDN)
        foreach ($Change in $Changes) {
            $FinalRows.Add((New-AuditRow -EventContext $Context -AuditType 'GPO Inheritance' -Action $Change.Action -GPOName '' -GPOGuid '' -TargetType $Change.TargetType -TargetName $Change.TargetName -TargetDN $Change.TargetDN -ChangedSetting $Change.ChangedSetting -PreviousValue $Change.PreviousValue -NewValue $Change.NewValue -ADAttribute 'gPOptions' -AttributionNote ''))
        }
    }
}

# ----------------------------------------------------------------------------
# GPO OBJECT / SETTING CHANGES
# ----------------------------------------------------------------------------

$GPOEvents = @($RawEvents | Where-Object { $_.RecordType -eq 'GPO' })

# First create logical operations using correlation ID.
$GPOOperationGroups = @(
    $GPOEvents |
    Group-Object {
        $Corr = $_.CorrelationID
        if ([string]::IsNullOrWhiteSpace($Corr) -or $Corr -eq '-') {
            $Corr = "RID-$($_.EventRecordID)"
        }
        "$($_.DomainController)|$($_.User)|$($_.GPOGuid)|$Corr"
    }
)

$GPOOperations = New-Object System.Collections.Generic.List[object]

foreach ($Group in $GPOOperationGroups) {
    $Events = @($Group.Group | Sort-Object EventRecordID)
    $First = $Events[0]
    $EventIDs = @($Events.EventID | Sort-Object -Unique)

    $Action = if ($EventIDs -contains 5141) { 'Deleted' }
              elseif ($EventIDs -contains 5137) { 'Created' }
              else { 'Modified' }

    $GPOOperations.Add([pscustomobject]@{
        TimeCreated      = $First.TimeCreated
        DomainController = $First.DomainController
        User             = $First.User
        Action           = $Action
        GPOGuid          = $First.GPOGuid
        CorrelationID    = $First.CorrelationID
        Events           = $Events
        Attributes       = @($Events.Attribute | Where-Object { $_ } | Sort-Object -Unique)
        EventIDs         = ($EventIDs -join '; ')
        EventRecordIDs   = (@($Events.EventRecordID | Sort-Object) -join '; ')
    })
}

# Directly report meaningful GPO metadata changes such as displayName.
foreach ($Operation in $GPOOperations) {
    $DisplayNameEvents = @($Operation.Events | Where-Object { $_.Attribute -eq 'displayName' })
    if ($DisplayNameEvents.Count -gt 0) {
        $OldName = @($DisplayNameEvents | Where-Object { $_.Operation -eq 'Value Deleted' } | Select-Object -Last 1).Value
        $NewName = @($DisplayNameEvents | Where-Object { $_.Operation -eq 'Value Added' }   | Select-Object -Last 1).Value
        if ($OldName -is [array]) { $OldName = $OldName[-1] }
        if ($NewName -is [array]) { $NewName = $NewName[-1] }

        $Context = [pscustomobject]@{
            TimeCreated      = $Operation.TimeCreated
            DomainController = $Operation.DomainController
            User             = $Operation.User
            CorrelationID    = $Operation.CorrelationID
            EventIDs         = $Operation.EventIDs
            EventRecordIDs   = $Operation.EventRecordIDs
        }

        $FinalRows.Add((New-AuditRow -EventContext $Context -AuditType 'GPO Metadata' -Action 'GPO Renamed' -GPOName ([string]$NewName) -GPOGuid $Operation.GPOGuid -ChangedSetting 'GPO display name' -PreviousValue ([string]$OldName) -NewValue ([string]$NewName) -ADAttribute 'displayName' -AttributionNote ''))
    }
}

# Compare each affected GPO once to the previous report snapshot.
$ByGPO = @($GPOOperations | Group-Object GPOGuid)

foreach ($GPOGroup in $ByGPO) {
    $Operations = @($GPOGroup.Group | Sort-Object TimeCreated)
    $Guid = $Operations[0].GPOGuid

    $DeletedOperation = @($Operations | Where-Object { $_.Action -eq 'Deleted' } | Select-Object -Last 1)
    $CreatedOperation = @($Operations | Where-Object { $_.Action -eq 'Created' } | Select-Object -First 1)

    $OverallAction = if ($DeletedOperation.Count -gt 0) { 'Deleted' }
                     elseif ($CreatedOperation.Count -gt 0 -and -not (Test-Path (Get-SnapshotFile -Guid $Guid))) { 'Created' }
                     else { 'Modified' }

    $Server = ($Operations | Select-Object -Last 1).DomainController
    $Comparison = Compare-GPOToSnapshot -Guid $Guid -Action $OverallAction -Server $Server
    $SnapshotUpdates[$Guid] = $Comparison

    $Changes = @($Comparison.Changes)

    # Ignore pure versionNumber / gPC* bookkeeping when the report has no real setting difference.
    $MeaningfulAttributes = @(
        $Operations.Attributes |
        Where-Object { $_ -and $_ -notin @('versionNumber','gPCMachineExtensionNames','gPCUserExtensionNames') } |
        Sort-Object -Unique
    )

    if ($Changes.Count -eq 0 -and $OverallAction -eq 'Modified') {
        if ($MeaningfulAttributes.Count -eq 0) {
            # No actual setting difference was found; suppress version-number-only noise.
            continue
        }

        $Changes = @([pscustomobject]@{
            Action         = 'GPO Modified'
            ChangedSetting = "GPO configuration changed ($($MeaningfulAttributes -join ', '))"
            PreviousValue  = ''
            NewValue       = ''
        })
    }

    $AttributionOperations = @($Operations | Where-Object { $_.Action -eq $OverallAction -or $OverallAction -eq 'Modified' })
    if ($AttributionOperations.Count -eq 0) { $AttributionOperations = $Operations }

    $DistinctUsers = @($AttributionOperations.User | Sort-Object -Unique)
    $LatestOp = $AttributionOperations | Select-Object -Last 1

    if ($AttributionOperations.Count -eq 1) {
        $Context = [pscustomobject]@{
            TimeCreated      = $LatestOp.TimeCreated
            DomainController = $LatestOp.DomainController
            User             = $LatestOp.User
            CorrelationID    = $LatestOp.CorrelationID
            EventIDs         = $LatestOp.EventIDs
            EventRecordIDs   = $LatestOp.EventRecordIDs
        }
        $AttributionNote = ''
    }
    else {
        $Context = [pscustomobject]@{
            TimeCreated      = $LatestOp.TimeCreated
            DomainController = (@($AttributionOperations.DomainController | Sort-Object -Unique) -join '; ')
            User             = ($DistinctUsers -join '; ')
            CorrelationID    = (@($AttributionOperations.CorrelationID | Where-Object { $_ } | Sort-Object -Unique) -join '; ')
            EventIDs         = (@($AttributionOperations.EventIDs | Sort-Object -Unique) -join '; ')
            EventRecordIDs   = (@($AttributionOperations.EventRecordIDs) -join '; ')
        }
        $AttributionNote = "Net GPO configuration difference across $($AttributionOperations.Count) operations during this polling interval; individual setting-to-admin attribution cannot be guaranteed."
    }

    $GPOName = Resolve-GPOName -Guid $Guid -Server $Server
    $AllAttributes = @($Operations.Attributes | Where-Object { $_ } | Sort-Object -Unique) -join '; '

    foreach ($Change in $Changes) {
        $AuditType = if ($Change.Action -match '^GPO (Created|Deleted)$') { 'GPO Lifecycle' } else { 'GPO Setting' }

        $FinalRows.Add((New-AuditRow -EventContext $Context -AuditType $AuditType -Action $Change.Action -GPOName $GPOName -GPOGuid $Guid -ChangedSetting $Change.ChangedSetting -PreviousValue $Change.PreviousValue -NewValue $Change.NewValue -ADAttribute $AllAttributes -AttributionNote $AttributionNote))
    }
}

# ============================================================================
# WRITE / SNAPSHOT / STATE
# ============================================================================

$SortedRows = @($FinalRows | Sort-Object TimeCreated,AuditType,GPOName,TargetName,ChangedSetting)
$Persisted = Write-AuditRows -Rows $SortedRows

if ($Persisted) {
    foreach ($Guid in $SnapshotUpdates.Keys) {
        $Snapshot = $SnapshotUpdates[$Guid]
        if ($Snapshot.SaveSnapshot -and $Snapshot.CurrentXML) {
            try {
                Set-Content -Path $Snapshot.SnapshotFile -Value $Snapshot.CurrentXML -Encoding UTF8 -Force -ErrorAction Stop
                Write-Verbose "Updated snapshot: $Guid"
            }
            catch {
                Write-Warning "Unable to update GPO snapshot for ${Guid}: $($_.Exception.Message)"
            }
        }
        elseif (-not $Snapshot.SaveSnapshot -and -not $Snapshot.CurrentXML) {
            # Deleted GPO: keep the old snapshot so its previous name/config remains available for audit reference.
        }
    }

    foreach ($DC in $StateUpdates.Keys) {
        try {
            Set-StateValue -Path $StateUpdates[$DC].StateFile -RecordID $StateUpdates[$DC].UpperRecordID
        }
        catch {
            Write-Warning "$DC state update failed: $($_.Exception.Message)"
        }
    }
}
else {
    Write-Warning 'State files were not advanced because audit output could not be persisted.'
}

# ============================================================================
# CONSOLE OUTPUT
# ============================================================================

Write-Host ''
Write-Host "Audit rows found: $($SortedRows.Count)"
Write-Host ''

if ($SortedRows.Count -gt 0) {
    $SortedRows |
        Select-Object TimeCreated,User,AuditType,Action,GPOName,TargetName,ChangedSetting,PreviousValue,NewValue |
        Format-Table -Wrap -AutoSize
}
else {
    Write-Host 'No GPO setting or link changes found.'
}

Write-Host ''
Write-Host "CSV:       $CsvPath"
Write-Host "State:     $StatePath"
Write-Host "Snapshots: $SnapshotPath"
Write-Host ''
