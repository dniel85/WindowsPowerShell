#===============================================================================
#
#          FILE: Move-NessusFiles.ps1
# 
#         USAGE: ./Move-NessusFiles.ps1
# 
#   DESCRIPTION: 
# 
#       OPTIONS: ---
#  REQUIREMENTS: ---
#         NOTES: ---
#       CREATED: 09/14/2017 01:12:21 PM EDT
#      REVISION:  $Rev: 1756 $
#===============================================================================


#function Move-NessusFiles () {
 <#
  .SYNOPSIS
  Describe the function here
  .DESCRIPTION
  Describe the function in more detail
  .EXAMPLE
  Give an example of how to use it
  .EXAMPLE
  Give another example of how to use it
  .PARAMETER computername
  The computer name to query. Just one.
  .PARAMETER logname
  The name of a file to write failed computer names to. Defaults to errors.txt.
  #>

  #The following modules will be ran 
    #preRun
        #Create Variables
        #Run as root
        #Check if Directories exist if not create
    #End of PreRun
    
    #prepFiles

    #moveFiles
    #endRun

    #variables 
    $topDir = "c:\nessusdata"
    $logDir = "$topDir\logs"
    $logFile = [string]::Concat($logDir,"\",$timeStamp.log)
    $nsocDir = "$topDir\NSOC"
    $lastMonth = (Get-Date).AddMonths(-1).ToString("MMMyyyy")
    $thisMonth = (Get-Date).ToString("MMMyyyy")
    $timeStamp = get-date
    $thisMonthPath = [string]::Concat($nsocDir,"\",$thisMonth)
    $lastMonthPath = [string]::Concat($nsocDir,"\",$lastMonth)
    $destDirA = "$topDir\cm1\connector.remote.nessusV2Compliance\new"
    $destDirB = "$topDir\cm2\connector.remote.nessusV2Compliance\new"
    $destDirC = "$topDir\cm3\connector.remote.nessusV2Compliance\new"
    $destDirD = "$topDir\cm4\connector.remote.nessusV2Compliance\new"
    $destDirE = "$topDir\cm5\connector.remote.nessusV2Compliance\new"
    $destDirF = "$topDir\cm6\connector.remote.nessusV2Compliance\new"
    
    

 #Run as root 
    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator"))
        {
            Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
            break

        }


    Write-Host "Begining run: $timeStamp" 
    
            
# Checking if directories exist if not creating them

    if(!(Test-Path -path "$topDir\logDir")) {
        New-Item -itemType directory -path $topDir\logDir -ErrorAction SilentlyContinue
    }
    if(!(Test-Path -path "$topDir\oldDir")) {
        New-Item -itemType directory -path $topDir\oldDir -ErrorAction SilentlyContinue
    }
    if(!(Test-Path -path "$topDir\archivegDir")) {
        New-Item -itemType directory -path $topDir\archiveDir -ErrorAction SilentlyContinue
    }
    if(!(Test-Path -path "$topDir\uncompDir")) {
        New-Item -itemType directory -path $topDir\uncompgDir -ErrorAction SilentlyContinue
    }
    if(!(Test-Path -Path "$topDir\NSOC")){
        New-Item -ItemType Directory -Path $topDir\NSOC -ErrorAction SilentlyContinue
    }

#end of PreRun
    write-host "Starting Prepfiles"

    $chkLastmonth = Test-Path $lastMonthPath
    $chkThismonth = Test-Path $thisMonthPath

    if ($chkLastmonth -eq $true){
        Remove-Item -path $lastMonthPath -Recurse
        Write-host "Removing superseded updates"
        }
    
    else {
          Get-ChildItem $nsocDir -Filter *.zip | Expand-Archive -DestinationPath $nsocDir -Force
          Set-Location -Path $nsocDir 
          #Remove-Item '.\*.zip' -Force
        }
  
    Get-ChildItem $nsocDir -Filter *.zip | Expand-Archive -DestinationPath 'C:\nessusdata\unZip' -Force
    Set-Location -Path $nsocDir 
    Remove-Item '.\*.zip' -Force
      

     write-host "Starting File Migration to connectors, this may take a while...." 

     


        # release archive object to prevent leaking resources
       
    #}#End of Function
