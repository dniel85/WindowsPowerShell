Write-host "***********************************************Type Get-Menu***********************************************" -BackgroundColor "black" -ForegroundColor "cyan" 
Function Get-Menu
{
    write-Host " 
    *************************************************************************************************************
    # ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄       ▄    ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄         ▄  ▄ #
    #▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌     ▐░▌  ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░▌#
    #▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌ ▀▀▀▀█░█▀▀▀▀      ▐░▌ ▐░▌  ▀▀▀▀█░█▀▀▀▀  ▀▀▀▀█░█▀▀▀▀  ▀▀▀▀█░█▀▀▀▀ ▐░▌       ▐░▌▐░▌#
    #▐░▌          ▐░▌       ▐░▌     ▐░▌          ▐░▌▐░▌       ▐░▌          ▐░▌          ▐░▌     ▐░▌       ▐░▌▐░▌#
    #▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌     ▐░▌          ▐░▌░▌        ▐░▌          ▐░▌          ▐░▌     ▐░█▄▄▄▄▄▄▄█░▌▐░▌#
    #▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌     ▐░▌          ▐░░▌         ▐░▌          ▐░▌          ▐░▌     ▐░░░░░░░░░░░▌▐░▌#
    #▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌     ▐░▌          ▐░▌░▌        ▐░▌          ▐░▌          ▐░▌      ▀▀▀▀█░█▀▀▀▀ ▐░▌#
    #▐░▌          ▐░▌       ▐░▌     ▐░▌          ▐░▌▐░▌       ▐░▌          ▐░▌          ▐░▌          ▐░▌      ▀ #
    #▐░▌          ▐░▌       ▐░▌     ▐░▌          ▐░▌ ▐░▌  ▄▄▄▄█░█▄▄▄▄      ▐░▌          ▐░▌          ▐░▌      ▄ #
    #▐░▌          ▐░▌       ▐░▌     ▐░▌          ▐░▌  ▐░▌▐░░░░░░░░░░░▌     ▐░▌          ▐░▌          ▐░▌     ▐░▌#
    # ▀            ▀         ▀       ▀            ▀    ▀  ▀▀▀▀▀▀▀▀▀▀▀       ▀            ▀            ▀       ▀ #
    #                                                                                                           #
    #                                                                                                           #
    #                              1.      ActiveDirectory Administration Menu                                  #
    #                              2.      Delete-Logs  (Delete log files)                                      #
    #                              3.      Transfer-Data (Transfer Large Data)                                  #
    #                              4.      New-IsoFile (Creates .iso files)                                     #
    #                              5.      Get-UsersandGroups                                                   #
    #                              6.      Get-LoggedOnUser                                                     #
    #                              7.      DBA Menu                                                             #
    #                              8.      Get-something (Search Workstation or server for files                #
    #                                                                                                           #
    #                                                                                                           #
    #                                                                                                           #
    #                                                                                                           #
    #                                                                                                           #
    *************************************************************************************************************" -BackgroundColor "black" -ForegroundColor Cyan                                                                                                           
    $answer = Read-Host -Prompt "Make a Selection Or Press Q to quit or lo to log out" #-BackgroundColor "black" -ForegroundColor Cyan 
    switch ($answer)
    {
        1 {Get-ADmenu}
        8 {get-something}
        2 {Delete-Logs} 
        3 {Transfer-Data} 
        4 {New-IsoFile}
        5 {Get-UsersandGroups}
        6 {Get-LoggedOnUser}
        7 {Get-DBAMenu}
       'Q'{exit}
       'lo'{shutdown /l}
    }
}
     
function Get-DBAMenu
{


write-Host 
"**********************************************************
#              DBA_FaT_KiTtY!!!!                          #
#                                                         #
#   1.      Install-DbaTools (tool Installer)             #
#   2.      List DBA Tools Library                        #
**********************************************************" 
$dbaanswer = read-Host -Prompt "Make a Selection Or Press Q to quit" 

switch ($dbaanswer)
    {
        1 {Install-Dbatools}
        2 {C:\Users\Darre\Documents\WindowsPowerShell\Scripts\DBAlibrary.ps1}
       'Q'{exit}   
    
    }

}

function Get-ADmenu
{

}

function get-something
{
<#
.SYNOPSIS
search for files 
.DESCRIPTION
Quick and easy power search that allows you to retrive the locations of files and folders. 
.EXAMPLE
PS C:\Users\dnielsen.adm> get-something
enter the name of the file you are searching for, Use Wildcards (*) if needed: asdf.*
C:\Users\dnielsen.adm\Desktop\asdf.bat
PS C:\Users\dnielsen.adm>
#>


$serachName = Read-Host -prompt "enter the name of the file you are searching for, Use Wildcards (*) if needed"

    Get-ChildItem -Path \  -Filter $serachName -Recurse -ErrorAction SilentlyContinue -Force | %{$_.FullName} 


$answer = read-Host -Prompt "Press 1 to go back to menu, Press Q to quit." 
Read-Host "Searching for files..."

switch ($answer)
{
    1 {Get-menu}
   'q' {exit} 
}

}


function Delete-Logs
{
[CmdletBinding()]
Param(
        [Parameter(Mandatory=$true,Position=1)]
        [String]$ComputerName
        )

#$SVRS = Read-Host -Prompt "Enter Server Names where you want to perform Log cleanup seperated with a (,)"

$credPro = Read-Host -Prompt "Enter your Admin credentials"

invoke-command -ComputerName $SVRS -ScriptBlock 
        { 
            $items = get-childitem -Path 'E:\Logs' | 
            ? {$_.name -like "Archive*.evtx" -and $_.LastWriteTime -lt (get-date).AddDays(-5)
        } -Credential $credPro
        If($items.count -gt 0)
            {
            $items | % {Remove-Item $_.FullName -Force -Confirm:$false
            }
            $answer = read-Host -Prompt "Press 1 to go back to menu, Press Q to quit." 

            switch ($answer)
        {
        1 {Get-menu}
       'q' {exit} 
        } 
     } 
    }
}

function Transfer-Data
{
#Set Parameters
Param(
    [Parameter(Mandatory=$true)]
    [String]$source,
    [Parameter(Mandatory=$true)]
    [String]$Destination
    )
xcopy.exe /T /E $source $Destination /Y

Get-ChildItem -Path $source -Recurse | ?{$_.PSisContainer} | 
    foreach {$spath = $_.FullName.Remove(0,$source.Length+1); 
    Start-BitsTransfer -Source $source\$spath\*.* $Destination\$spath}
    
    Start-BitsTransfer $source\*.* $Destination -Verbose
    $answer = read-Host -Prompt "Press 1 to go back to menu, Press Q to quit." 

switch ($answer)
    {
        1 {Get-menu}
       'q' {exit} 
    }
}
function New-IsoFile  
{  
  <#  
   .Synopsis  
    Creates a new .iso file  
   .Description  
    The New-IsoFile cmdlet creates a new .iso file containing content from chosen folders  
   .Example  
    New-IsoFile "c:\tools","c:Downloads\utils"  
    This command creates a .iso file in $env:temp folder (default location) that contains c:\tools and c:\downloads\utils folders. The folders themselves are included at the root of the .iso image.  
   .Example 
    New-IsoFile -FromClipboard -Verbose 
    Before running this command, select and copy (Ctrl-C) files/folders in Explorer first.  
   .Example  
    dir c:\WinPE | New-IsoFile -Path c:\temp\WinPE.iso -BootFile "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\efisys.bin" -Media DVDPLUSR -Title "WinPE" 
    This command creates a bootable .iso file containing the content from c:\WinPE folder, but the folder itself isn't included. Boot file etfsboot.com can be found in Windows ADK. Refer to IMAPI_MEDIA_PHYSICAL_TYPE enumeration for possible media types: http://msdn.microsoft.com/en-us/library/windows/desktop/aa366217(v=vs.85).aspx  
   .Notes 
    NAME:  New-IsoFile  
    AUTHOR: Chris Wu 
    LASTEDIT: 03/23/2016 14:46:50  
 #>  
  
 
  [CmdletBinding(DefaultParameterSetName='Source')]Param( 
    [parameter(Position=1,Mandatory=$true,ValueFromPipeline=$true, ParameterSetName='Source')]$Source,  
    [parameter(Position=2)][string]$Path = "$env:temp\$((Get-Date).ToString('yyyyMMdd-HHmmss.ffff')).iso",  
    [ValidateScript({Test-Path -LiteralPath $_ -PathType Leaf})][string]$BootFile = $null, 
    [ValidateSet('CDR','CDRW','DVDRAM','DVDPLUSR','DVDPLUSRW','DVDPLUSR_DUALLAYER','DVDDASHR','DVDDASHRW','DVDDASHR_DUALLAYER','DISK','DVDPLUSRW_DUALLAYER','BDR','BDRE')][string] $Media = 'DVDPLUSRW_DUALLAYER', 
    [string]$Title = (Get-Date).ToString("yyyyMMdd-HHmmss.ffff"),  
    [switch]$Force, 
    [parameter(ParameterSetName='Clipboard')][switch]$FromClipboard 
  ) 
 
  Begin {  
    ($cp = new-object System.CodeDom.Compiler.CompilerParameters).CompilerOptions = '/unsafe' 
    if (!('ISOFile' -as [type])) {  
      Add-Type -CompilerParameters $cp -TypeDefinition @' 
public class ISOFile  
{ 
  public unsafe static void Create(string Path, object Stream, int BlockSize, int TotalBlocks)  
  {  
    int bytes = 0;  
    byte[] buf = new byte[BlockSize];  
    var ptr = (System.IntPtr)(&bytes);  
    var o = System.IO.File.OpenWrite(Path);  
    var i = Stream as System.Runtime.InteropServices.ComTypes.IStream;  
  
    if (o != null) { 
      while (TotalBlocks-- > 0) {  
        i.Read(buf, BlockSize, ptr); o.Write(buf, 0, bytes);  
      }  
      o.Flush(); o.Close();  
    } 
  } 
}  
'@  
    } 
  
    if ($BootFile) { 
      if('BDR','BDRE' -contains $Media) { Write-Warning "Bootable image doesn't seem to work with media type $Media" } 
      ($Stream = New-Object -ComObject ADODB.Stream -Property @{Type=1}).Open()  # adFileTypeBinary 
      $Stream.LoadFromFile((Get-Item -LiteralPath $BootFile).Fullname) 
      ($Boot = New-Object -ComObject IMAPI2FS.BootOptions).AssignBootImage($Stream) 
    } 
 
    $MediaType = @('UNKNOWN','CDROM','CDR','CDRW','DVDROM','DVDRAM','DVDPLUSR','DVDPLUSRW','DVDPLUSR_DUALLAYER','DVDDASHR','DVDDASHRW','DVDDASHR_DUALLAYER','DISK','DVDPLUSRW_DUALLAYER','HDDVDROM','HDDVDR','HDDVDRAM','BDROM','BDR','BDRE') 
 
    Write-Verbose -Message "Selected media type is $Media with value $($MediaType.IndexOf($Media))" 
    ($Image = New-Object -com IMAPI2FS.MsftFileSystemImage -Property @{VolumeName=$Title}).ChooseImageDefaultsForMediaType($MediaType.IndexOf($Media)) 
  
    if (!($Target = New-Item -Path $Path -ItemType File -Force:$Force -ErrorAction SilentlyContinue)) { Write-Error -Message "Cannot create file $Path. Use -Force parameter to overwrite if the target file already exists."; break } 
  }  
 
  Process { 
    if($FromClipboard) { 
      if($PSVersionTable.PSVersion.Major -lt 5) { Write-Error -Message 'The -FromClipboard parameter is only supported on PowerShell v5 or higher'; break } 
      $Source = Get-Clipboard -Format FileDropList 
    } 
 
    foreach($item in $Source) { 
      if($item -isnot [System.IO.FileInfo] -and $item -isnot [System.IO.DirectoryInfo]) { 
        $item = Get-Item -LiteralPath $item    
      } 
 
      if($item) { 
        Write-Verbose -Message "Adding item to the target image: $($item.FullName)" 
        try { $Image.Root.AddTree($item.FullName, $true) } catch { Write-Error -Message ($_.Exception.Message.Trim() + ' Try a different media type.') } 
      } 
    } 
  } 
 
  End {  
    if ($Boot) { $Image.BootImageOptions=$Boot }  
    $Result = $Image.CreateResultImage()  
    [ISOFile]::Create($Target.FullName,$Result.ImageStream,$Result.BlockSize,$Result.TotalBlocks) 
    Write-Verbose -Message "Target image ($($Target.FullName)) has been created" 
    $Target 
  } 
} 
 Function Get-Folder($initialDirectory)
{
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")

    $foldername = New-Object System.Windows.Forms.FolderBrowserDialog
    $foldername.RootFolder = "MyComputer"

    if($foldername.ShowDialog() -eq "OK")
    {
        $folder += $foldername.SelectedPath
    }
    return $folder
    $answer = read-Host -Prompt "Press 1 to go back to menu, Press Q to quit." 

    switch ($answer)
    {
        1 {Get-menu}
       'q' {exit} 
    }
}

function Get-UsersandGroups
{
Import-Module ActiveDirectory

$ou ="OU=CLAY,DC=clay,DC=vdc,DC=cmil,DC=mil"
$groups = (Get-ADGroup -Filter * | Where {$_.name -like "**"} | select name -ExpandProperty name) 

$Table = @()
$Record = [ordered]@{
"group Name" = ""
"Name" = ""
"Username" = ""
}

Foreach ($Group in $Groups)
    {

    $Arrayofmembers = Get-ADGroupMember -Identity $group -recursive | select name,samaccountname

        foreach ($Member in $Arrayofmembers)
        {
        $Record."group Name" = $Group
        $Record."name" = $member.name
        $Record."Username" = $member.samacocuntname
        $objRecord = New-Object PSObject -Property $Record
        $Table += $objRecord
        }

    }

$Table | Export-Csv "C:\users\dnielsen.adm\Desktop\securityGroups.csv" -NoTypeInformation
}

function Get-LoggedOnUser { 
#Requires -Version 2.0             
[CmdletBinding()]             
 Param              
   (                        
    [Parameter(Mandatory=$true, 
               Position=0,                           
               ValueFromPipeline=$true,             
               ValueFromPipelineByPropertyName=$true)]             
    [String[]]$ComputerName 
   )#End Param 
 
Begin             
{             
 Write-Host "`n Checking Users . . . " 
 $i = 0             
}#Begin           
Process             
{ 
    $ComputerName | Foreach-object { 
    $Computer = $_ 
    try 
        { 
            $processinfo = @(Get-WmiObject -class win32_process -ComputerName $Computer -EA "Stop") 
                if ($processinfo) 
                {     
                    $processinfo | Foreach-Object {$_.GetOwner().User} |  
                    Where-Object {$_ -ne "NETWORK SERVICE" -and $_ -ne "LOCAL SERVICE" -and $_ -ne "SYSTEM"} | 
                    Sort-Object -Unique | 
                    ForEach-Object { New-Object psobject -Property @{Computer=$Computer;LoggedOn=$_} } |  
                    Select-Object Computer,LoggedOn 
                }#If 
        } 
    catch 
        { 
            "Cannot find any processes running on $computer" | Out-Host 
        } 
            $answer = read-Host -Prompt "Press 1 to go back to menu, Press Q to quit." 

            switch ($answer)
        {
            1 {Get-menu}
           'q' {exit} 
     }#Forech-object(Comptuters)        
             
}#Process 
End 
{ 
 
}#End 
 
}#Get-LoggedOnUser 
}

function Install-DBAtools
{
Remove-Module dbatools -ErrorAction SilentlyContinue
$url = 'https://github.com/ctrlbold/dbatools/archive/master.zip'
$path = Join-Path -Path (Split-Path -Path $profile) -ChildPath '\Modules\dbatools'
$temp = ([System.IO.Path]::GetTempPath()).TrimEnd("\")
$zipfile = "$temp\sqltools.zip"

if (!(Test-Path -Path $path)){
	Write-Output "Creating directory: $path"
	New-Item -Path $path -ItemType Directory | Out-Null 
} else { 
	Write-Output "Deleting previously installed module"
	Remove-Item -Path "$path\*" -Force -Recurse 
}

Write-Output "Downloading archive from github"
try
{
	Invoke-WebRequest $url -OutFile $zipfile
} catch {
   #try with default proxy and usersettings
   Write-Output "Probably using a proxy for internet access, trying default proxy settings"
   (New-Object System.Net.WebClient).Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
   Invoke-WebRequest $url -OutFile $zipfile
}

# Unblock if there's a block
Unblock-File $zipfile -ErrorAction SilentlyContinue

Write-Output "Unzipping"
# Keep it backwards compatible
$shell = New-Object -COM Shell.Application
$zipPackage = $shell.NameSpace($zipfile)
$destinationFolder = $shell.NameSpace($temp)
$destinationFolder.CopyHere($zipPackage.Items())

Write-Output "Cleaning up"
Move-Item -Path "$temp\dbatools-master\*" $path
Remove-Item -Path "$temp\dbatools-master"
Remove-Item -Path $zipfile

Import-Module "$path\dbatools.psd1" -Force

Write-Output "Done! Please report any bugs to clemaire@gmail.com."
Get-Command -Module dbatools
Write-Output "`n`nIf you experience any function missing errors after update, please restart PowerShell or reload your profile."

}


function Start-PowerUpdate 
{ 
Import-Module BitsTransfer, PSWindowsUpdate
    $isofileNM = Read-Host -Prompt "please enter .iso filename"
   # $xmlgzfile = Read-Host -Prompt "please enter name of xml.gz file"
    
    Mount-DiskImage -ImagePath g:\$isofileNM


    #Moving GZ
    Move-Item -Path g:\$isofileNM\*.tar.gz -Destination C:\tar.gz_UPDATE

    #Moving Content

   # Start-BitsTransfer -Source G:\$isofileNM -Description "Moving Content" -Destination \\clayobmwss01\d$\WSUS\WsusContent 
    Transfer-Data -source G:\*.* -Destination \\clayobmwss01\d$\WSUS\WsusContent 
    Transfer-Data -source C:\tar.gz_UPDATE\*.tar.gz -Destination '\\clayobmwss01\c$\Temp'

}


