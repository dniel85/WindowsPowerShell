# List of URLs to scrape
$urls = @(
    "https://definitions.symantec.com/defs/download/symantec_enterprise/jdb/core3sds/index.html",
    "https://definitions.symantec.com/defs/download/symantec_enterprise/jdb/core15sds/index.html",
    "https://definitions.symantec.com/defs/ips/",
    "http://definitions.symantec.com/defs/sonar/",
    "https://definitions.symantec.com/defs/sef/"
)
#do stuff
function Download-File {
    param (
        [string]$url,
        [string]$destinationFolder
    )
    try{
        $fileName = [System.IO.Path]::Combine($destinationFolder, [System.IO.Path]::GetFileName($url)) 
        Invoke-WebRequest -Uri $url -OutFile $fileName 
        Write-Host "Downloaded: $fileName"
    } 
    catch{
        Write-Host "Error downloading `$url: $_"
    }
}
#get stuff
function Get-DownloadableLinks {
    param (
        [string]$url
    )
    try{
        $todaysDate = ((get-date).ToString("yyyyMM"))
        $response = Invoke-WebRequest -Uri $url
     
        $links = $response.Links | Where-Object {$_.href -match '\bhttps?://(?:\S*RU8\S*)\.jdb\b' -or $_.href -match 'sdsn64' }
   
        $downloadableLinks = $links | ForEach-Object { [uri]::new($url).GetLeftPart([System.UriPartial]::Authority) + $_.href}
    
        return $downloadableLinks
    } 
    catch{
        Write-Host "Error retrieving links from `$url: $_"
        return @()
    }
}

#seperate stuff
foreach ($url in $urls){
    $folderName = ($url.TrimEnd('/').Split('/')[-1])

    if($folderName -eq 'index.html') {$folderName = ($url.TrimEnd('/').Split('/')[-2])}
    
    $downloadDir = "N:\Transfer\av_defs"
    
    if (-Not (Test-Path -Path $downloadDir)) {
        New-Item -ItemType Directory -Path $downloadDir
        }
    if (-not (test-path -Path $downloadDir\$folderName)) {
        New-Item -ItemType Directory -Path $downloadDir\$folderName
        }
    $downloadableLinks = Get-DownloadableLinks -url $url
    
    foreach ($link in $downloadableLinks) {
        if($link -match 'sonar'){
        Download-File -url ($link -replace '^http://definitions.symantec.com','') -destinationFolder $downloadDir\$foldername 
        }
    else{
        Download-File -url ($link -replace '^https://definitions.symantec.com','') -destinationFolder $downloadDir\$foldername 
        }
    }
    Write-Host "All downloads completed for $folderName!"
}
Write-Host "All downloads from all URLs completed!"