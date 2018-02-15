$Url = 'https://technet.microsoft.com/en-us/security/rss/bulletin'
$ExcludeProducts = 'lync|Itanium|for mac'
$IncludeProducts = 'server'

$ExcludePatches = '-IA64|Windows6\.0|-RT-|ServiceBusServer'

$PatchStoreTo = '.\'

$WebClient = New-Object System.Net.WebClient
$WebClient.Encoding = [System.Text.Encoding]::UTF8

do
{
    $RSSContent = $WebClient.DownloadString($Url)
}
while(
    $(if(!$?)
    {
        Write-Host 'Failed to get RSS' -ForegroundColor Red
        Start-Sleep -Seconds 600
        $true
    })
)

([xml]$RSSContent).rss.channel.Item | Sort-Object link | %{
    $MSRC_URL = $_.link
    Write-Host "Processing: [$MSRC_URL]" -ForegroundColor Yellow
    $MSRC = ([regex]::Match($MSRC_URL, '(?i)MS\d+-\d+$')).Value
    Write-Host "MS number: [$MSRC]" -ForegroundColor Green
    if(!(Test-Path -LiteralPath "$PatchStoreTo\$MSRC"))
    {
        do
        {
            New-Item -Path "$PatchStoreTo\$MSRC" -ItemType Directory | Out-Null
        }
        while(
            $(if(!$?)
            {
                Write-Host 'Failed to create MSRC folder' -ForegroundColor Red
                Start-Sleep 300
                $true
            })
        )
    }
    Write-Host "Trying to capture KBs from MSRC URL" -ForegroundColor Yellow
    do
    {
        $MSContent = $null
        $MSContent = $WebClient.DownloadString($MSRC_URL)
    }
    while(
        $(if(!$?)
        {
            Write-Host 'Failed to capture MSRC content' -ForegroundColor Red
            Start-Sleep 300
            $true
        })
    )
    
    [regex]::Matches($MSContent, '(?i)<tr>[\s\S]+?<a href="(https?://www.microsoft.com/downloads/details.aspx\?FamilyID=[\w\-]+?)">[\s\S]*?(\d{7})') | %{
        Write-Host "KB: [$($_.Groups[2].Value)]" -NoNewline -ForegroundColor Green
        if($_.Value -imatch $ExcludeProducts)
        {
            Write-Host "   --- Excluded: [$($Matches[0])]" -ForegroundColor Red
        }
        else
        {
            if($_.Value -notmatch $IncludeProducts)
            {
                Write-Host "   --- Excluded: Not match [$IncludeProducts]" -ForegroundColor Red
                return
            }
            $KBNumber = "KB$($_.Groups[2].Value)"
            Write-Host "`nDownload URL: [$($_.Groups[1].Value)]" -ForegroundColor Gray
<#
            if(!(Test-Path -Path "$MSRC\$KBNumber"))
            {
                do
                {
                    New-Item -Name "$MSRC\$KBNumber" -ItemType Directory | Out-Null
                }
                while(
                    $(if(!$?)
                    {
                        Write-Host 'Failed to create KB folder' -ForegroundColor Red
                        Start-Sleep 300
                        $true
                    })
                )
            }
#>
            do
            {
                $KBContent = $null
                $KBContent = $WebClient.DownloadString($_.Groups[1].Value)
            }while(
                $(if(!$?)
                {
                    Write-Host 'Failed to capture KB content' -ForegroundColor Red
                    Start-Sleep 300
                    $true
                })
            )

            $KBConfirm = ([regex]::Match($KBContent, '(?i)href="(confirmation.aspx\?id=\d+)"')).Groups[1].Value
            $KBConfirm = "http://www.microsoft.com/en-us/download/$KBConfirm"
            Write-Host "KB confirm URL: [$KBConfirm]" -ForegroundColor Gray
            do
            {
                $KBContent = $null
                $KBContent = $WebClient.DownloadString($KBConfirm)
            }while(
                $(if(!$?)
                {
                    Write-Host 'Failed to capture KB download content' -ForegroundColor Red
                    Start-Sleep 300
                    $true
                })
            )

            $KBLinks = @()
            $KBLinks = [regex]::Matches($KBContent, '(?i)<a href="(http://download.microsoft.com/download/.+?)".+?>Click here</span>') | %{
                $_.Groups[1].Value
            }
            $KBLinks = @($KBLinks | Sort-Object -Unique)
            Write-Host "The KB contains updates: [$($KBLinks.Count)]" -ForegroundColor Green
            $KBLinks | %{
                $FileName = $null
                $FileName = $_.Split('/')[-1]
                if($FileName -imatch $ExcludePatches)
                {
                    Write-Host "Patch excluded: [$($Matches[0])]" -ForegroundColor Red
                    return
                }
                $FilePath = $null
                $FilePath = "$MSRC\$FileName"
                Write-Host "Going to download file: [$FilePath]" -ForegroundColor Gray
                $FilePath = "$PatchStoreTo\$FilePath"
                if(Test-Path -Path $FilePath)
                {
                    Write-Host 'File already exists, skip!' -ForegroundColor Gray
                }
                else
                {
                    do
                    {
                        $WebClient.DownloadFile($_, $FilePath)
                    }while(
                        $(if(!$?)
                        {
                            Write-Host 'Download file failed!' -ForegroundColor Red
                            Start-Sleep -Seconds 300
                            $true
                        })
                    )
                }
            }
        }
    }
}