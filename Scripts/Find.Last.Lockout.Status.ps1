[cmdletbinding()]
    param(
        [parameter(mandatory=$true)]
        $username
        )

Get-ADDomainController -Filter * | ForEach-Object{
    Get-WinEvent -ComputerName $_.hostname -FilterHashtable @{LogName='Security';ID=4740} | Where-Object {$_.Message -like '*$username*'} |
     Select-Object timecreated, @{Name='Computer';Expression={($_.properties[1].value)}}, Message
    }


    

