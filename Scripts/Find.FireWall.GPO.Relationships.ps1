Import-Module GroupPolicy

# ------------------------------------------------------------
# Helper: Resolve resource strings like @FirewallAPI.dll,-2878
# ------------------------------------------------------------
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

# ------------------------------------------------------------
# Helper: Get node text from XML
# ------------------------------------------------------------
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

# ------------------------------------------------------------
# Main loop: iterate all GPOs
# ------------------------------------------------------------
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

# ------------------------------------------------------------
# Output
# ------------------------------------------------------------
if ($results.Count -eq 0) {
    Write-Warning "No firewall rules found in any GPOs."
} else {
    $results | Sort-Object GPOName, RuleName | Format-Table -AutoSize
    # Optional CSV export:
    # $results | Export-Csv "GPO_Firewall_Rules.csv" -NoTypeInformation
}
