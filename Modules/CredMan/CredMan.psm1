. .\Path\To\CredMan.ps1  
 
function Main 
{ 
#region Adding credentials 
    if($AddCred) 
    { 
        if([String]::IsNullOrEmpty($User) -or 
           [String]::IsNullOrEmpty($Pass)) 
        { 
            Write-Host "You must supply a user name and password (target URI is optional)." 
            return 
        } 
        # may be [Int32] or [Management.Automation.ErrorRecord] 
        [Object] $Results = Write-Creds $Target $User $Pass $Comment $CredType $CredPersist 
        if(0 -eq $Results) 
        { 
            [Object] $Cred = Read-Creds $Target $CredType 
            if($null -eq $Cred) 
            { 
                Write-Host "Credentials for '$Target', '$User' was not found." 
                return 
            } 
            if($Cred -is [Management.Automation.ErrorRecord]) 
            { 
                return $Cred 
            } 
            [String] $CredStr = @" 
Successfully wrote or updated credentials as: 
  UserName  : $($Cred.UserName) 
  Password  : $($Cred.CredentialBlob) 
  Target    : $($Cred.TargetName.Substring($Cred.TargetName.IndexOf("=")+1)) 
  Updated   : $([String]::Format("{0:yyyy-MM-dd HH:mm:ss}", $Cred.LastWritten.ToUniversalTime())) UTC 
  Comment   : $($Cred.Comment) 
"@ 
            Write-Host $CredStr 
            return 
        } 
        # will be a [Management.Automation.ErrorRecord] 
        return $Results 
    } 
#endregion     
 
#region Removing credentials 
    if($DelCred) 
    { 
        if(-not $Target) 
        { 
            Write-Host "You must supply a target URI." 
            return 
        } 
        # may be [Int32] or [Management.Automation.ErrorRecord] 
        [Object] $Results = Del-Creds $Target $CredType  
        if(0 -eq $Results) 
        { 
            Write-Host "Successfully deleted credentials for '$Target'" 
            return 
        } 
        # will be a [Management.Automation.ErrorRecord] 
        return $Results 
    } 
#endregion 
 
#region Reading selected credential 
    if($GetCred) 
    { 
        if(-not $Target) 
        { 
            Write-Host "You must supply a target URI." 
            return 
        } 
        # may be [PsUtils.CredMan+Credential] or [Management.Automation.ErrorRecord] 
        [Object] $Cred = Read-Creds $Target $CredType 
        if($null -eq $Cred) 
        { 
            Write-Host "Credential for '$Target' as '$CredType' type was not found." 
            return 
        } 
        if($Cred -is [Management.Automation.ErrorRecord]) 
        { 
            return $Cred 
        } 
        [String] $CredStr = @" 
Found credentials as: 
  UserName  : $($Cred.UserName) 
  Password  : $($Cred.CredentialBlob) 
  Target    : $($Cred.TargetName.Substring($Cred.TargetName.IndexOf("=")+1)) 
  Updated   : $([String]::Format("{0:yyyy-MM-dd HH:mm:ss}", $Cred.LastWritten.ToUniversalTime())) UTC 
  Comment   : $($Cred.Comment) 
"@ 
        Write-Host $CredStr 
    } 
#endregion 
 
#region Reading all credentials 
    if($ShoCred) 
    { 
        # may be [PsUtils.CredMan+Credential[]] or [Management.Automation.ErrorRecord] 
        [Object] $Creds = Enum-Creds 
        if($Creds -split [Array] -and 0 -eq $Creds.Length) 
        { 
            Write-Host "No Credentials found for $($Env:UserName)" 
            return 
        } 
        if($Creds -is [Management.Automation.ErrorRecord]) 
        { 
            return $Creds 
        } 
        foreach($Cred in $Creds) 
        { 
            [String] $CredStr = @" 
             
UserName  : $($Cred.UserName) 
Password  : $($Cred.CredentialBlob) 
Target    : $($Cred.TargetName.Substring($Cred.TargetName.IndexOf("=")+1)) 
Updated   : $([String]::Format("{0:yyyy-MM-dd HH:mm:ss}", $Cred.LastWritten.ToUniversalTime())) UTC 
Comment   : $($Cred.Comment) 
"@ 
            if($All) 
            { 
                $CredStr = @" 
$CredStr 
Alias     : $($Cred.TargetAlias) 
AttribCnt : $($Cred.AttributeCount) 
Attribs   : $($Cred.Attributes) 
Flags     : $($Cred.Flags) 
Pwd Size  : $($Cred.CredentialBlobSize) 
Storage   : $($Cred.Persist) 
Type      : $($Cred.Type) 
"@ 
            } 
            Write-Host $CredStr 
        } 
        return 
    } 
#endregion 
 
#region Run basic diagnostics 
    if($RunTests) 
    { 
        [PsUtils.CredMan]::Main() 
    } 
#endregion 
} 