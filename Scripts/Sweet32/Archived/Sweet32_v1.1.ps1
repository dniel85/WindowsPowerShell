# Title = SSL Medium Strength Cipher Suite Supported (SWEET32)
# Tenable Plugin-ID = 42873
# Organization = 692d COS/CYS - SIL IA Team
# Creator = Chris Bullington / Nate Martinez
# Date = 20230710
#
#     Change Log
#     7/11/2023 - v1.0 - Original CB/NM
#     7/12/2023 - v1.1 - Updated to compare between Server 2012 R2/ and all other OS's
#
##
## This script will disable 3DES and RC4 Ciphers on the local system(s)
## To manually identify which Ciphers are running on your system execute the following command:
##
## Get-TlsCipherSuite              (e.g. Get-TlsCipherSuite > c:\temp\sweet32.txt)
##
## Open sweet32.txt file, Ctrl + F and type Cipher you wish to disable, scroll down to name field and highlight your selection

$Computers = Get-Content -Path "E:\Scripts\Sweet32\test.txt"
foreach ($comp in $Computers){
    Write-Host "Disable TLS cipher suite on $computer.."
    $session = New-PSSession -ComputerName $comp
    Invoke-Command -Session $session -ScriptBlock{
    #Get-ADComputer -Filter {OperatingSystem -Like "Windows*"} -Properties OperatingSystem | Select -ExpandProperty OperatingSystem 
     If($OSVersion -eq "Windows Server 2012*"){
     New-Item -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" -Force |
     New-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" -Name "Enabled" -PropertyType DWORD -Value "0x0" -Force
    }
     If($OSVersion -ne "Windows Server 2012*"){
     Disable-TlsCipherSuite -Name 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'|
     Disable-TlsCipherSuite -Name 'TLS_RSA_WITH_RC4_128_SHA'
    } 
   }
    Remove-PSSession -Session $session
}
