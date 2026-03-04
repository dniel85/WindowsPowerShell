if($WinServers -eq $null){New-Variable -name WinServers -value  @(get-adcomputer -Filter {operatingsystem -like "*windows server*" -and Enabled -eq "True"}).name -Scope global
    }

$roleNameMap = @{
    "dc"  = "DomainController"
    "wec" = "WindowsEventCollector"
    "fs"  = "FileShare"
    "sql" = "Databases"
    "lr"  = "LogRhythm"
    "vdi" = "Citrix"
    "sen" = "Sentris"
    "iat" = "Nessus"
    "ps1" = "print"
    "wsus"= "UpdateServer"
    "dhcp" = "DHCP"
    "sep" =  "Symantic"
    "fp" =   "ForcePoint"
    }

$iniFile = "$env:userprofile\documents\windowspowershell\files\Servers.ini"
if(test-path $inifile) {remove-item $inifile}

$RoleGroups = @{}

foreach($server in $WinServers){
    $parts = $server -split "-"
    
    $middleParts = $parts[1..($parts.Count -2)]

    $rolekey = $null
    foreach ($part in $middleParts){

        $cleanPart = ($part -replace "\d","").ToLower()
        if($cleanPart){
            $roleKey = $cleanPart
            break
        }
    }

    if(-not $rolekey){
        $rolekey=($parts[1] -replace "\d","").ToLower()
    }

    
    if($roleNameMap.ContainsKey($rolekey)){
        $roleName = $roleNameMap[$rolekey]
    } 
    else {
        $roleName = (Get-Culture).TextInfo.ToTitleCase($rolekey)
    }
    if (-not $RoleGroups.ContainsKey($rolename)){
        $RoleGroups[$roleName] = @()
    }
    $rolegroups[$roleName] += $server
}

Add-Content -Path $iniFile -Value "; Servers categorized by auto-detected role"
Add-Content -Path $iniFile -Value "; Generated on $(get-date)"
add-content -Path $iniFile -Value ""

foreach($role in $RoleGroups.Keys){
    Add-Content -Path $iniFile -Value "[$role]"
    foreach($srv in $RoleGroups[$role]){
        Add-Content -Path $iniFile -Value "server=$srv"
    }
    Add-Content -Path $iniFile -Value ""

}
Write-Output "INI file created: $iniFile"
