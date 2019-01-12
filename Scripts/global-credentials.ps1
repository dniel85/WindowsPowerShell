$user = "Niagara.mil\darrell.nielsen.sa"
$Pwd = ConvertTo-SecureString -String "free123BEER!@#" -AsPlainText -Force
$global:SA_Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user, $Pwd

$DAuser = "Niagara.mil\darrell.nielsen.da"
$DAPwd = ConvertTo-SecureString -String "free123BEER!@#" -AsPlainText -Force
$global:DA_Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $DAuser, $DAPwd
