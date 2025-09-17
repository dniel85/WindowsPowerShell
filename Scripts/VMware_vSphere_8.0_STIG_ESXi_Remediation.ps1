[CmdletBinding()]
param (
  [Parameter(Mandatory=$true)]
  [string]$vcenter,
  [Parameter(Mandatory=$true)]
  [pscredential]$vccred,
  [Parameter(Mandatory=$true,ParameterSetName="hostname")]
  [string]$hostname,
  [Parameter(Mandatory=$true,ParameterSetName="cluster")]
  [string]$cluster,
  [Parameter(Mandatory=$false,
  HelpMessage="Enter the path for the output report. Example /tmp")]
  [string]$reportpath,  
  [Parameter(Mandatory=$true,
  HelpMessage="Enter the Active Directory Admins group to use for administrative access to ESXi")]
  [string]$esxAdminGroup,
  [Parameter(Mandatory=$true,
  HelpMessage="Enter allowed IP ranges for the ESXi firewall in comma separated format.  For Example "192.168.0.0/16","10.0.0.0/8" ")]
  [string[]]$allowedIPs,
  [Parameter(Mandatory=$false,
  HelpMessage="Enter the syslog server for the ESXi server(s). Example tcp://log.domain.local:514")]
  [string]$syslogServer,
  [Parameter(Mandatory=$false,
  HelpMessage="Enable this option if VMware vRealize Log Insight is used to manage syslog on the ESXi host(s).")]
  [switch]$logInsight,
  [Parameter(Mandatory=$true,
  HelpMessage="Enter NTP servers.  For Example "10.1.1.1","10.1.1.2" ")]
  [string[]]$ntpServers,
  [Parameter(Mandatory=$false,
  HelpMessage="Specify the native VLAN Id configured on the ports going to the ESXi Hosts.  If none is specified the default of 1 will be used.")]
  [string]$nativeVLAN = "1"
)
