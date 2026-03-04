# Title = SSL Medium Strength Cipher Suite Supported (SWEET32)
# Tenable Plugin-ID = 42873
# Organization = 692d COS/CYS - SIL IA Team
# Creator = Chris Bullington / Nate Martinez
# Date = 20230710
#
#     Change Log
#     7/11/2023 - v1.0 - Original CB/NM
#
##
## This script will disable 3DES and RC4 Ciphers on the local system(s)
## To manually identify which Ciphers are running on your system execute the following command:
##
## Get-TlsCipherSuite              (e.g. Get-TlsCipherSuite > c:\temp\sweet32.txt)
##
## Open sweet32.txt file, Ctrl + F and type Cipher you wish to disable, scroll down to name field and highlight your selection

# Enter path to server.txt (e.g. "c:\sweet32\server.txt")
$Computers = Get-Content -Path "PATH TO SERVER.TXT FILE"

foreach ($computer in $Computers){
    Write-Host "Disable TLS cipher suite on $computer .."
    #Estabilishes PSSession for each computer in the $computers "server.txt" file
    $session = New-PSSession -ComputerName $computer
    #Disables TLS 3DES / RC4 on each computer
    Invoke-Command -Session $session -ScriptBlock{
    Disable-TlsCipherSuite -Name 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'|
    Disable-TlsCipherSuite -Name 'TLS_RSA_WITH_RC4_128_SHA'
    }
    #Disconnects each PSSession
    Remove-PSSession -Session $session
}