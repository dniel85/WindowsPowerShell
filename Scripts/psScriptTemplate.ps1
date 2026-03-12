#requires -version 2
<#
.SYNOPSIS
  <Overview of script>
.DESCRIPTION
  <Brief description of script>
.PARAMETER <Parameter_Name>
    <Brief description of parameter input required. Repeat this attribute if required>
.INPUTS
  <Inputs if any, otherwise state None>
.OUTPUTS
  <Outputs if any, otherwise state None - example: Log file stored in C:\Windows\Temp\<name>.log>
.NOTES
  Version:        1.0
  Author:         Darrell Nielsen
  Creation Date:  <Date>
  Purpose/Change: Initial script development

  Tags:
    <script tags>
  
.EXAMPLE
  <Example goes here. Repeat this attribute for more than one example>
#>
[cmdletbinding()]
param()
#--------------------------------------------------------[Required Modules]--------------------------------------------------------
import-module PSlogging
#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Script Version
$sScriptVersion = "1.0"
Write-Log -Debug -Message "Running $Global:scriptname Version $sScriptVersion" -level DEBUG
#Set Powershell 5 - 7 enablement
$requiresPowerShell7=$false
Write-Log -Debug -Message "requires PS7 set to :: $requiresPowerShell7" -Level DEBUG

#Run as admin (default = false)
$RunAsAdmin = $true
Write-Log -Debug -Message "requires runAs Admin set to :: $RunAsAdmin" -Level DEBUG

#Script Name
$global:scrptName = $MyInvocation.MyCommand.Name

#Set Error Action to Silently Continue
$ErrorActionPreference = "SilentlyContinue"

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

if($requiresPowerShell7){
  Write-Host "This Script requires Powershell 7. Enabling now..." -ForegroundColor DarkGray
  try{ pwsh.exe}catch [System.Management.Automation.CommandNotFoundException]{
    Write-Log -message "[Initialisations] ERROR: $global:scrptName, must be ran using PowerShell 7" -level ERROR
  }
}
if($RunAsAdmin -eq $true){
  $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal   = New-Object Security.Principal.WindowsPrincipal($currentUser)

  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
      Write-log -message "[Initialisations] $global:scrptName must be ran as Administrator." -level ERROR
      return
  }
}
#-----------------------------------------------------------[Functions]------------------------------------------------------------

<#
Function <FunctionName>{
  Param(
    [Parameter(
    Mandatory=$true,
    ValueFromPipeline=$false,
    ValueFromPipelineByPropertyName=$false,
    Position=0
    )]
    [ValidateNotNullOrEmpty()]
    [string]$ParameterName
    )
  
  Begin{
  write-log -message "[begin]"
    Log-Write -LogPath $sLogFile -LineValue "<description of what is going on>..."
  }
  
  Process{
    Try{
      <code goes here>
    }
    
    Catch{
      Log-Error -LogPath $sLogFile -ErrorDesc $_.Exception -ExitGracefully $True
      Break
    }
  }
  
  End{
    If($?){
      Log-Write -LogPath $sLogFile -LineValue "Completed Successfully."
      Log-Write -LogPath $sLogFile -LineValue " "
    }
  }
}
#>

#-----------------------------------------------------------[Execution]------------------------------------------------------------

Write-Log "Start of script" 

#Logic here


Write-Log "end of script"