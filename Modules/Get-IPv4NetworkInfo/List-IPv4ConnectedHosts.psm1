<#  
.SYNOPSIS  
    Performs a Ping sweep on local network and connected hosts.
.DESCRIPTION  
    Itterates through each Ip Address on subnet and outputs all hosts
    that are connected.
 
.PARAMETER IPAddress 
IP Address of any ip within the network
Note: Exclusive from @CIDRAddress
 
.PARAMETER SubnetMask
Subnet Mask of the network.
Note: Exclusive from @CIDRAddress
 
.PARAMETER CIDRAddress
CIDR Notation of IP/Subnet Mask (x.x.x.x/y)
Note: Exclusive from @IPAddress and @SubnetMask
 
.PARAMETER IncludeIPRange
Switch parameter that defines whether or not the script will return an array
of usable host IP addresses within the defined network.
Note: This parameter can cause delays in script completion for larger subnets.
 
.EXAMPLE
Get-IPv4NetworkInfo -IPAddress 192.168.1.23 -SubnetMask 255.255.255.0
 
Get network information with IP Address and Subnet Mask
 
.EXAMPLE
Get-IPv4NetworkInfo -CIDRAddress 192.168.1.23/24
 
Get network information with CIDR Notation
 
.NOTES  
    File Name  : List-IPv4ConnectedHosts.ps1
    Author     : Darrell Nielsen
    Date       : 5/10/16
    Requires   : PowerShell v3
.LINK  
www.ryandrane.com
#>
 
Function List-IPv4ConnectedHosts
{
    [cmdletbinding()]
    Param
    (
        [int]$StartingIP,
        [int]$EndingIP
    )


    if(-not(get-module -ListAvailable -Name Get-IPv4NetworkInfo)){
        Write-Warning "Module Get-IPv4NetworkInfo Must be Installed before running"
        }
        else{Import-Module Get-IPv4NetworkInfo}

    $HostIP = (
        Get-NetIPConfiguration |Where-Object {
        $_.IPv4DefaultGateway -ne $null -and
        $_.NetAdapter.Status -ne "Disconnected"}).IPv4Address.IPAddress

    [int]$CIDR = (
        Get-NetIPConfiguration |Where-Object {
        $_.IPv4DefaultGateway -ne $null -and
        $_.NetAdapter.Status -ne "Disconnected"}).IPv4Address.prefixLength

    $ip_CIDR = "$($HostIP)/$($CIDR)"

    $IPinfo = Get-IPv4NetworkInfo -CIDRAddress $ip_CIDR

    $subNet = $IPinfo.NetworkAddress
    $ping = 1
    $ip = $subNet -replace "\.\d{1,3}$"

    Write-Host "
IP_ADDRESS  CONNECTED
----------------------"

    while ($StartingIP -le $EndingIP){
    Write-Debug $StartingIP
    Write-Debug $EndingIP
        $ipNet = "$($ip).$($StartingIP)"
        Write-Debug $ipNet
        $TC = Test-Connection -ComputerName $ipNet -Count 1 -Quiet

        #$DNSGet = Resolve-DnsName $ipNet needs to be fixed 
        #$DNSname = $DNSGet.nameHost
        $StartingIP++

        Write-Host "$ipNet      $tc"

    }
}