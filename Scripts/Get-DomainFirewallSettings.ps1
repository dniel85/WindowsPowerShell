if($winservers -eq $null) {$winservers = @(Get-Content 'C:\STiG_Findings\ops\ExceptADM.txt')

    }
Invoke-Command -ComputerName $winservers -ScriptBlock {
    $profiles = Get-NetFirewallProfile | Select-Object Name,Enabled
    $map = @{}
    foreach ($item in $profiles){
        $map[$item.name] = $item.enabled
    }
    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        Domain       = $map['Domain']
        Private      = $map['Private']
        Public       = $map['Public']
    }
} | Format-Table ComputerName, Domain,Private,Public -AutoSize