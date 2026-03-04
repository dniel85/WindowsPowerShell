# Title = SSL Medium Strength Cipher Suite Supported (SWEET32)
# Title2 = SSL RC4 Cipher Suites Supported (Bar Mitzvah)
# Tenable Plugin-ID = 42873
# Organization = 692d COS/CYS - SIL IA Team
# Creator = Chris Bullington / Nate Martinez
# Date = 20230710
#
#     Change Log
#     7/11/2023 - v1.0 - Original CB/NM
#     7/12/2023 - v1.1 - Updated to compare between Server 2012 R2/ and all other OS's
#     7/13/2023 - v1.2 - Microsoft 'Shaun Evans' assisted in rewrite.  Added all enabled systems / SSL RC4 Cipher Suites Supported (Bar Mitzvah) for Windows Server 2012 R2 / Removed manual change requirements
#
##
## This script will disable 3DES and RC4 Ciphers on the local system(s)
## To manually identify which Ciphers are running on your system execute the following command:
##
## Get-TlsCipherSuite              (e.g. Get-TlsCipherSuite > c:\temp\sweet32.txt)
##
## Open sweet32.txt file, Ctrl + F and type Cipher you wish to disable, scroll down to name field and highlight your selection

#$Idenify = Get-ADComputer -Filter 'Enabled -eq "true"' | Select -ExpandProperty Name | Out-File C:\users\you\example.txt
#$Idenify = Get-ADComputer -Filter 'Enabled -eq "true"' | FT DNSHostName > C:\TEMP\Servers.txt
#$Computers = Get-Content -Path "C:\TEMP\Servers.txt"

$Computers = Get-ADComputer -Filter 'Enabled -eq "true"' 

Invoke-Command -ComputerName $($Computers.Name) -ErrorAction SilentlyContinue -ErrorVariable RegError -ScriptBlock {
    
    $OSVersion = $(Get-CimInstance -ClassName Win32_OperatingSystem).Caption

    If($OSVersion -like "*2012*"){
       # Disabling 3DES / RC4
        $schannel = Get-Item HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
        $ciphers = $schannel.OpenSubKey('Ciphers', $true)
        $key = $ciphers.CreateSubKey('Triple DES 168')
        $key.SetValue('Enabled', 0x0)
        $key = $ciphers.CreateSubKey('RC4 40/128')
        $key.SetValue('Enabled', 0x0)
        $key = $ciphers.CreateSubKey('RC4 56/128')
        $key.SetValue('Enabled', 0x0)
        $key = $ciphers.CreateSubKey('RC4 128/128')
        $key.SetValue('Enabled', 0x0)
    }
    If($OSVersion -notlike "*2012*"){
       # Disabling 3DES
       Disable-TlsCipherSuite -Name 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA' -ErrorAction SilentlyContinue
       Disable-TlsCipherSuite -Name 'TLS_RSA_WITH_3DES_EDE_CBC_SHA' -ErrorAction SilentlyContinue
       # Disabling RC4
       Disable-TlsCipherSuite -Name 'TLS_RSA_WITH_RC4_128_MD5' -ErrorAction SilentlyContinue
       Disable-TlsCipherSuite -Name 'TLS_RSA_WITH_RC4_128_SHA' -ErrorAction SilentlyContinue
    }
}

# List of system(s) with connection errors
#$RegError.CategoryInfo | Select TargetName, Reason # | Out-File .\MissedComps.txt
