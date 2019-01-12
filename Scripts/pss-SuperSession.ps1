 
$user = "Niagara.mil\darrell.nielsen.sa"
$Pwd = ConvertTo-SecureString -String "free123BEER!@#" -AsPlainText -Force
$global:SA_Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user, $Pwd

$DAuser = "Niagara.mil\darrell.nielsen.da"
$DAPwd = ConvertTo-SecureString -String "free123BEER!@#" -AsPlainText -Force
$global:DA_Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $DAuser, $DAPwd
 
 write-Host " 
    *************************************************
    #                                               #
    #                                               #
    #                 1.      DCO1                  #
    #                 2.      DCO2                  #
    #                 3.      BAS01                 #
    #                 4.      BAS02                 #
    #                 5.      FS1                   #
    #                 6.      FS2                   #
    #                 7.      WDS1                  #
    #                 8.      WSUS1                 #
    #                                               #
    #                                               #
    #                                               #
    #                                               #
    #                                               #
    *************************************************" -BackgroundColor "black" -ForegroundColor Yellow                                                                                                           
    $answer = Read-Host -Prompt "Make a Selection Or Press Q to quit or lo to log out" 
    switch ($answer)
    {
        1 {Enter-pssession -computername niagaradco1 -credential $global:DA_credential}
        2 {Enter-pssession -computername niagaradco2 -credential $global:DA_credential}
        3 {Enter-pssession -computername bas-websrv-01 -credential $global:SA_credential}
        4 {Enter-pssession -computername bas-websrv-02 -credential $global:SA_credential}
        5 {Enter-pssession -computername NIAGARAFS1 -credential $global:SA_credential}
        6 {Enter-pssession -computername NIAGARAFS2 -credential $global:SA_credential}
        7 {Enter-pssession -computername NIAGARAWDS01 -credential $global:SA_credential}
        8 {Enter-pssession -computername NIAGARAWSUS1 -credential $global:SA_credential}
       'Q'{exit}
       'lo'{shutdown /l}

    }


