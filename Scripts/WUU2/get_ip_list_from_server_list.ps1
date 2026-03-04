<#
.DESCRIPTION
    Grab IP addresses from DNS for all servers in a list (.txt/.csv) and then
    dump them to a txt file to copy into tenable.
.NOTES
    Author: SIL Atom / Colby Dibble
    Created Apr2023
.EXAMPLE
    Get-IPListFromServerList.ps1
#>
$List = @()
function Get-FileName($initialDirectory){

    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.InitialDirectory = $initialDirectory
    $OpenFileDialog.Filter = "TXT (*.txt) | *.txt|CSV (*.csv) | *.csv"
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.FileName
}

$InputFile = Get-FileName $env:USERPROFILE\Desktop

if($InputFile -like "*.csv"){

    $InputData = Import-Csv $InputFile
}
else{

    $InputData = get-content $InputFile
}


foreach($Server in $InputData){

    if($server.GetType().Name -notlike "String"){
        $List += Get-DnsServerResourceRecord -ZoneName (Get-ADDomain).forest -ComputerName (Get-ADDomainController).hostname -Name $server.name
    }
    else{
        $List += Get-DnsServerResourceRecord -ZoneName (Get-ADDomain).forest -ComputerName (Get-ADDomainController).hostname -Name $server
    }
    

}

$list.RecordData.ipv4address -join "," | Out-File $env:USERPROFILE\Desktop\IPList.txt
