. C:\ScheduledTasks\WindowsPowerShell\Scripts\LoggingFunction.ps1 
<#
.SYNOPSIS
    This function processes a file provided by the user.

.DESCRIPTION
    This function accepts a file path as input. It checks if the file exists at the specified path.
    The file path must be a valid file on the system.

.PARAMETER FilePath
    The full path to the file that needs to be processed. This parameter is mandatory and must be a valid file path.

.EXAMPLE
    Download-AVdefs -Path "C:\path\to\file.txt"
    This will run the function and retrieve the latest Symantec updates from the urls listed in the URL variable below. 

.NOTES
    Author: Darrell Nielsen
    Email: darrell.nielsen@mantech.com
    Date: 2024-12-10
#>

Function Download-AVdefs{
    Param(
        [CmdletBinding()]
        [parameter(Mandatory=$true, HelpMessage="Ënter a Network path to where the AV updates will be downloaded")]
        [validateScript({
        if (-not (Test-Path $_ )) {
        throw [system.io.filenotfoundexception] "$_ is not a valid file path.Check local or UNC path and try again."
        }
        return $true   
        })]
        [string]$Path,
        [switch]$LogEnabled  # Define a parameter for logging control
    )
    #This function downloads the files

        function Download-File{
            param (
                [string]$url,
                [string]$destinationFolder
            )
            Write-Host $url
            $fun = $MyInvocation.MyCommand.Name
            Write-Log -level INFO -message "[$fun] starting function download-file" -LogEnabled:$LogEnabled
            Write-Log -Level INFO -message "[$fun] Downloading:: `n $url to $destinationfolder" -LogEnabled:$LogEnabled
            try{
                $fileName = [System.IO.Path]::Combine($destinationFolder, [System.IO.Path]::GetFileName($url)) 
                Write-Log -level INFO -message "[$fun] combine destination folder and url using value $filename" -LogEnabled:$LogEnabled
                Invoke-WebRequest -Uri $url -OutFile $fileName 
                Write-Log -level INFO -message "[$fun] Invoking webrequest and downloading $url to filename" -LogEnabled:$LogEnabled
            } 
        
            catch {
                   throw Write-Log -level ERROR -message "[$fun] $($errorDetails.Exception.Message) `nRemote webserver may be down or links contained in the `$urls array are incorrect" -LogEnabled:$LogEnabled
                   
                }
            }
    
        #This function filters the downloadable links to the desired updates needed by using regex to filter the names of files needed.
        function Get-DownloadableLinks {
            param (
                [string]$url
            )
            $fun = $MyInvocation.MyCommand.Name
            Write-Log -Level INFO -Message "[$fun] Starting function Get-DownloadableLinks" -LogEnabled:$LogEnabled
            try{
                $response = Invoke-WebRequest -Uri $url
        
                $links = $response.Links | Where-Object {$_.href -match '\bhttps?://(?:\S*RU8\S*)\.jdb\b' -or $_.href -match 'sdsn64' }
                $downloadableLinks = $links | ForEach-Object { [uri]::new($url).GetLeftPart([System.UriPartial]::Authority) + $_.href}
                Write-Log -level INFO -message "[$fun] Parsing url download files into correct format to download files" -LogEnabled:$LogEnabled
                [int]$lastLink = ($downloadableLinks).Length -1
                return $downloadableLinks[[int]$lastLink]
            } 
            catch{
                Write-Log -level ERROR -message "[$fun] Error retrieving links from" $uri : $_
                return @()
            }
        }

        #This function cleans up superseeded update files in each folder.
        function Optimize-Directories{
            param(
                $directoryPath
                )
                $fun = $MyInvocation.MyCommand.Name
                Write-Log -level INFO -message "[$fun] Starting Function" -LogEnabled:$LogEnabled
                $files = Get-ChildItem -Path $directoryPath | Sort-Object LastWriteTime -Descending
                Write-Log -level INFO -message "[$fun] Getting files based on last write time" -LogEnabled:$LogEnabled
                $latestFile = $files | Select-Object -First 1
                $files | Where-Object { 
                    $_.FullName -ne $latestFile.FullName 
                    } | Remove-Item -Force
                Write-Log -level INFO -message "[$fun] Removing the following superseeded $files " -LogEnabled:$LogEnabled
            }



    #Main()
    $fun = $MyInvocation.MyCommand.Name+"(MAIN)"
    Write-Log -Level INFO -Message "***START OF SCRIPT***" -LogEnabled:$LogEnabled
    $drive = New-PSDrive -Name X -PSProvider FileSystem -Root $Path
    Write-Log -level INFO -message "[$fun] Creating PSDRIVE WITH PATH $Path" -LogEnabled:$LogEnabled
    
    #list of all urls for the symantec updates
    $urls = @(
    "https://definitions.symantec.com/defs/download/symantec_enterprise/jdb/core3sds/index.html"<#,
    "https://definitions.symantec.com/defs/download/symantec_enterprise/jdb/core15sds/index.html",
     "https://definitions.symantec.com/defs/ips/",
     "https://definitions.symantec.com/defs/sonar/index.html",
     "https://definitions.symantec.com/defs/sef/"#>
    )

    

    foreach ($url in $urls){
    Write-Log -level INFO -message "[$fun]  Processing url:: $url" -LogEnabled:$LogEnabled
    #foreach loop that trims each url name to create folders based on the url. 

   if ($folderName -like '*index.html') {
    # Extract the folder name from the URL by splitting the URL and getting the last part
    $folderName = ($url.TrimEnd('/').Split('/')[-1])
    Write-Log -Level INFO -Message "[$fun] Creating child directory path for download: $folderName" -LogEnabled $LogEnabled
    } else {
    # If the folder name contains 'index.html', get the second-to-last part
    $folderName = ($url.TrimEnd('/').Split('/')[-2])
    Write-Log -Level INFO -Message "[$fun] Creating child directory path for download: $folderName" -LogEnabled $LogEnabled
    }
    <#this is the directory the AV defs will be located. 
    It's using the psdrive created earlier with the path letter 
    which gives a root of  X:\\SIL-FAS\Transfer\__AV_defs.  
    #>


    $downloadDir = $drive.root+"\__AV_defs" 
    Write-Log -level INFO -message "[$fun] $downloadDir will be the root parent folder for av updates." -LogEnabled:$LogEnabled


    #tests if the $downloadDir path is valid. if not it creates it. 
    if (-Not (Test-Path -Path $downloadDir)) {
        Write-Log -level WARN -message "[$fun] $downloadDir does not exist!! creating child directory:: $folderName" -LogEnabled:$LogEnabled
        New-Item -ItemType Directory -Path $downloadDir
        }
    #tests if child directories exist. If not it creates them. 
    if (-not (test-path -Path $downloadDir\$folderName)) {
        Write-Log -level WARN -message "[$fun] $downloadDir does not exist!! creating child directory:: $folderName" -LogEnabled:$LogEnabled
        New-Item -ItemType Directory -Path $downloadDir\$folderName
        }
    
    # puts all downloadable links into a variable 
    $downloadableLinks = Get-DownloadableLinks -url $url

    #Downloads all the latest files and puts them in the correct directory.
    Download-File -url ($downloadablelinks -replace '^https://definitions.symantec.com','') -destinationFolder $downloadDir\$foldername
    
   
    Write-Log -level INFO -message "[$fun] Downloading symantic update:: $downloadablelinks to $downloadDir\$foldername"  -LogEnabled:$LogEnabled

    #removes all superseeded updates that are no longer needed
    Optimize-Directories -Directories -directoryPath "$downloadDir\$foldername"
    Write-Log -level INFO -message "[$fun] Calling function Optimize-Directories" -LogEnabled:$LogEnabled
    }
    Write-Log -level INFO -message "[$fun] All downloads from all URLs completed!" -LogEnabled:$LogEnabled
    #removes the temp drive created to run this script. 
    Remove-PSDrive -Name x -Force
    Write-Log -level INFO -message "[$fun] Removing PSdrive $drive" -LogEnabled:$LogEnabled
    Write-Log -level INFO -message "*** END OF SCRIPT ***" -LogEnabled:$LogEnabled
}

#test
Download-AVdefs -Path c:\temp -LogEnabled