function Recurse-OU ([string]$dn, $level = 1) 
{ 
    if ($level -eq 1) { $dn } 
    Get-ADOrganizationalUnit -filter * -SearchBase $dn -SearchScope OneLevel |  
        Sort-Object -Property distinguishedName |  
        ForEach-Object { 
            $components = ($_.distinguishedname).split(',') 
            "$('--' * $level) $($components[0])" 
            Recurse-OU -dn $_.distinguishedname -level ($level+1) 
        } 
} 
 
Recurse-OU -dn (Get-ADDomain).DistinguishedName | Out-File $env:USERPROFILE\desktop\Visual_OU_Structure.csv