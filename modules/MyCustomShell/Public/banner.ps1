function banner {
    [cmdletbinding()]
        param()
    $cacheDir  = Join-Path ([Environment]::GetFolderPath("MyDocuments")) 'PowerShell\Files'
    $cacheFile = Join-Path $cacheDir 'BannerInfo.txt'
    $tmpXml    = Join-Path $env:TEMP 'banner.xml'

    # Only do the expensive stuff if cache doesn't exist
    if (-not (Test-Path $cacheFile)) {

        Import-Module GroupPolicy -ErrorAction SilentlyContinue

        if (-not (Test-Path $cacheDir)) {
            New-Item -Path $cacheDir -ItemType Directory -Force | Out-Null
        }

        try {
            $gpo = Get-GPO -All |
                   Where-Object DisplayName -match "Banner" |
                   Select-Object -First 1
        }
        catch {
            return
        }

        if (-not $gpo) { return }

        try {
            Get-GPOReport -Guid $gpo.Id -ReportType Xml -Path $tmpXml | Out-Null
            [xml]$BannerXML = Get-Content $tmpXml
        }
        catch {
            return
        }
        finally {
            Remove-Item $tmpXml -Force -ErrorAction SilentlyContinue
        }

        $node = $BannerXML.SelectSingleNode("//EditText/Value")
        if ($node) { $displayText = $node.InnerText }

        $dropdowns = $BannerXML.SelectNodes("//DropDownList/Value")

        if ($dropdowns -and $dropdowns.Count -ge 2) {
            $foregroundColor = $dropdowns[1].name
            $backgroundColor = $dropdowns[0].name
        }

        if (-not $displayText) { return }

        @($displayText,$foregroundColor,$backgroundColor) |
            Set-Content $cacheFile -Encoding UTF8
    }

    # FAST PATH (runs every shell launch)
    $bannerContent = Get-Content $cacheFile -ErrorAction SilentlyContinue
    if (-not $bannerContent -or $bannerContent.Count -lt 3) { return }

    $width  = $Host.UI.RawUI.WindowSize.Width
    $status = $bannerContent[0]

    $leftPadding = [math]::Max(0, ($width - $status.Length) / 2)
    $line = (" " * [math]::Floor($leftPadding)) + $status
    $line = $line.PadRight($width)

    $fg = $bannerContent[1]
    $bg = $bannerContent[2]

    if ($bg -notmatch '^Dark') { $bg = "Dark$bg" }

    try {
        Write-Host $line -ForegroundColor $fg -BackgroundColor $bg
    }
    catch {
        Write-Host $line
    }
}