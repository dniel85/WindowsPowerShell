<#
.SYNOPSIS
Enumerates Windows Firewall rules configured in Group Policy Objects.

.DESCRIPTION
This script scans all Group Policy Objects (GPOs) in the domain and extracts
Windows Firewall rules defined within those policies.

The script retrieves each GPO using Get-GPO and generates an XML report using
Get-GPOReport. It then parses the XML to locate inbound and outbound firewall
rule definitions.

Firewall rule properties such as name, description, direction, action,
protocol, ports, application, service, and remote addresses are extracted and
returned as PowerShell objects.

If firewall rule names or descriptions are stored as Windows resource strings
(e.g., "@FirewallAPI.dll,-12345"), the script resolves them to their readable
text values using Win32 API calls.

Results are displayed in a formatted table sorted by GPO name and rule name.
An optional CSV export line is included for reporting or auditing purposes.

.PARAMETER None
This script does not accept parameters.

.EXAMPLE
.\Get-GPOFirewallRules.ps1

Scans all GPOs in the domain and displays firewall rules found within them.

.EXAMPLE
.\Get-GPOFirewallRules.ps1 | Export-Csv FirewallRules.csv -NoTypeInformation

Exports discovered firewall rules to a CSV file.

.INPUTS
None

.OUTPUTS
System.Management.Automation.PSCustomObject

Returned object properties include:

    GPOName
    RuleName
    Action
    Direction
    Protocol
    LocalPort
    App
    Service
    RemoteIPv4
    RemoteIPv6
    Description
    Active

.NOTES
Author: Darrell Nielsen
Created: 2026-03-06
Version: 1.0

Requirements:
- Active Directory domain environment
- GroupPolicy PowerShell module
- Permission to query GPO reports

Behavior:
- Enumerates all domain GPOs
- Parses firewall rules from GPO XML reports
- Resolves localized firewall rule strings
- Displays results in a formatted table

TAGS: GPO, GroupPolicy, Firewall, Security, WindowsFirewall, ActiveDirectory, Audit, STIG
#>
Import-Module GroupPolicy

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class Win32 {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int LoadString(IntPtr hInstance, int uID, StringBuilder lpBuffer, int nBufferMax);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr LoadLibrary(string lpFileName);
}
"@

function Resolve-ResourceString {
    param(
        [string]$ResourceString
    )

    if (-not $ResourceString -or $ResourceString -notmatch "^@(.+?),(?:-)?(\d+)$") {
        return $ResourceString
    }

    $dllPath = $matches[1]
    $resId   = [int]$matches[2]

    # Expand environment variables
    $dllPath = [Environment]::ExpandEnvironmentVariables($dllPath)

    $h = [Win32]::LoadLibrary($dllPath)
    if ($h -eq [IntPtr]::Zero) {
        return $ResourceString
    }

    $sb = New-Object System.Text.StringBuilder 1024
    $len = [Win32]::LoadString($h, $resId, $sb, $sb.Capacity)

    if ($len -gt 0) {
        return $sb.ToString()
    }

    return $ResourceString
}


function Get-NodeText {
    param(
        [System.Xml.XmlNode]$Node,
        [string]$XPath,
        [System.Xml.XmlNamespaceManager]$NsMgr
    )
    $found = $Node.SelectSingleNode($XPath, $NsMgr)
    if ($found -ne $null) { return $found.InnerText }
    return $null
}

$results = @()


Get-GPO -All | ForEach-Object {
    $gpo = $_
    Write-Host "Scanning GPO: $($gpo.DisplayName)" -ForegroundColor Cyan

    [xml]$xml = Get-GPOReport -Guid $gpo.Id -ReportType Xml

    # Namespace manager
    $nsMgr = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)

    # Register all namespaces automatically
    $xml.DocumentElement.Attributes |
        Where-Object { $_.Name -like "xmlns:*" } |
        ForEach-Object {
            $prefix = $_.Name.Split(':')[1]
            $nsMgr.AddNamespace($prefix, $_.Value)
        }

    # Find inbound and outbound rule nodes
    $ruleNodes = @(
        $xml.SelectNodes("//*[local-name()='InboundFirewallRules']", $nsMgr),
        $xml.SelectNodes("//*[local-name()='OutboundFirewallRules']", $nsMgr)
    ) | ForEach-Object { $_ } | Where-Object { $_ -ne $null }

    foreach ($ruleNode in $ruleNodes) {

        $nameRaw   = Get-NodeText -Node $ruleNode -XPath ".//*[local-name()='Name']" -NsMgr $nsMgr
        $descRaw   = Get-NodeText -Node $ruleNode -XPath ".//*[local-name()='Desc']" -NsMgr $nsMgr

        $name      = Resolve-ResourceString $nameRaw
        $desc      = Resolve-ResourceString $descRaw

        $action    = Get-NodeText -Node $ruleNode -XPath ".//*[local-name()='Action']" -NsMgr $nsMgr
        $direction = Get-NodeText -Node $ruleNode -XPath ".//*[local-name()='Dir']" -NsMgr $nsMgr
        $protocol  = Get-NodeText -Node $ruleNode -XPath ".//*[local-name()='Protocol']" -NsMgr $nsMgr
        $lport     = Get-NodeText -Node $ruleNode -XPath ".//*[local-name()='LPort']" -NsMgr $nsMgr
        $app       = Get-NodeText -Node $ruleNode -XPath ".//*[local-name()='App']" -NsMgr $nsMgr
        $svc       = Get-NodeText -Node $ruleNode -XPath ".//*[local-name()='Svc']" -NsMgr $nsMgr
        $ra4       = Get-NodeText -Node $ruleNode -XPath ".//*[local-name()='RA4']" -NsMgr $nsMgr
        $ra6       = Get-NodeText -Node $ruleNode -XPath ".//*[local-name()='RA6']" -NsMgr $nsMgr
        $active    = Get-NodeText -Node $ruleNode -XPath ".//*[local-name()='Active']" -NsMgr $nsMgr

        $results += [PSCustomObject]@{
            GPOName     = $gpo.DisplayName
            RuleName    = $name
            Action      = $action
            Direction   = $direction
            Protocol    = $protocol
            LocalPort   = $lport
            App         = $app
            Service     = $svc
            RemoteIPv4  = $ra4
            RemoteIPv6  = $ra6
            Description = $desc
            Active      = $active
        }
    }
}


if ($results.Count -eq 0) {
    Write-Warning "No firewall rules found in any GPOs."
} else {
    $results | Sort-Object GPOName, RuleName | Format-Table -AutoSize
    # Optional CSV export:
    # $results | Export-Csv "GPO_Firewall_Rules.csv" -NoTypeInformation
}
