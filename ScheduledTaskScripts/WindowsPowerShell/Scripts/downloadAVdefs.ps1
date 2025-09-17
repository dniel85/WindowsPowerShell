Start-Transcript -Path C:\temp\scripttranscript2.txt -Append

<#Creates a established connection to the root file system. Rename the drive letter to an unused letter and alter the path to your
desired location for the AV updates
#>
New-PSDrive -Name X -PSProvider FileSystem -Root \\SIL-FAS\Transfer 
#list of all urls for the symantec updates
$urls = @(
"https://definitions.symantec.com/defs/download/symantec_enterprise/jdb/core3sds/index.html",
"https://definitions.symantec.com/defs/download/symantec_enterprise/jdb/core15sds/index.html",
"https://definitions.symantec.com/defs/ips/",
"https://definitions.symantec.com/defs/sonar/index.html",
"https://definitions.symantec.com/defs/sef/"
)


#This function downloads the files
function Download-File {
    param (
        [string]$url,
        [string]$destinationFolder
    )
    try{
        Write-Host $url
        $fileName = [System.IO.Path]::Combine($destinationFolder, [System.IO.Path]::GetFileName($url)) 
        Write-Verbose $fileName 
        Invoke-WebRequest -Uri $url -OutFile $fileName 
        Write-Host "Downloaded: $fileName"
    } 
    catch{
        Write-Host "Error downloading" $url : $_
    }
}
#This function filters the downloadable links to the desired updates needed by using regex to filter the names of files needed.
function Get-DownloadableLinks {
    param (
        [string]$url
    )
    try{
        $response = Invoke-WebRequest -Uri $url
        
        $links = $response.Links | Where-Object {$_.href -match '\bhttps?://(?:\S*RU8\S*)\.jdb\b' -or $_.href -match 'sdsn64' }

        $downloadableLinks = $links | ForEach-Object { [uri]::new($url).GetLeftPart([System.UriPartial]::Authority) + $_.href}
        [int]$lastLink = ($downloadableLinks).Length -1
        return $downloadableLinks[[int]$lastLink]
    } 
    catch{
        Write-Host "Error retrieving links from `$url: $_"
        return @()
    }
}
#This function cleans up superseeded update files in each folder.
function Optimize-Directories{
    param(
        $directoryPath
        )
        
    $files = Get-ChildItem -Path $directoryPath | Sort-Object LastWriteTime -Descending
    $latestFile = $files | Select-Object -First 1
    $files | Where-Object { $_.FullName -ne $latestFile.FullName } | Remove-Item -Force
}


#Main()

foreach ($url in $urls){
Write-Host "URL in foreach loop" $url
#foreach loop that trims each url name to create folders based on the url. 
$folderName = ($url.TrimEnd('/').Split('/')[-1])
Write-Host "Foldername Created" $folderName
#continued trimming to get unique folder names
if($folderName -eq 'index.html') {$folderName = ($url.TrimEnd('/').Split('/')[-2])}
<#this is the directory the AV defs will be located. 
It's using the psdrive created earlier with the path letter 
which gives a root of  X:\\SIL-FAS\Transfer\__AV_defs.  
#>
$downloadDir = "X:\__AV_defs" #<----------------------------------------------------- EDIT THIS TO reflect share drive
#tests if the $downloadDir path is valid. if not it creates it. 
if (-Not (Test-Path -Path $downloadDir)) {
    New-Item -ItemType Directory -Path $downloadDir
    }
#tests if child directories exist. If not it creates them. 
if (-not (test-path -Path $downloadDir\$folderName)) {
    New-Item -ItemType Directory -Path $downloadDir\$folderName
    }
# puts all downloadable links into a variable 
$downloadableLinks = Get-DownloadableLinks -url $url
Write-Host $downloadableLinks
#Downloads all the latest files and puts them in the correct directory. 
Write-Host "download link is $link"
Download-File -url ($downloadablelinks -replace '^https://definitions.symantec.com','') -destinationFolder $downloadDir\$foldername 
#removes all superseeded updates that are no longer needed
Optimize-Directories -Directories -directoryPath "$downloadDir\$foldername"
Write-Host "All downloads completed for $folderName!"
}
Write-Host "All downloads from all URLs completed!"
#removes the temp drive created to run this script. 
Remove-PSDrive -Name x -Force

Stop-Transcript