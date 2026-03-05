function banner {
    $cacheDir  = Join-Path $env:USERPROFILE 'Documents\WindowsPowerShell\Files'
    $cacheFile = Join-Path $cacheDir 'BannerInfo.txt'
    $tmpXml    = Join-Path $env:TEMP 'banner.xml'

    # If cache doesn't exist, try to find and parse the Banner GPO
    if (-not (Test-Path $cacheFile)) {

        # Make sure the cache folder exists
        if (-not (Test-Path $cacheDir)) {
            New-Item -Path $cacheDir -ItemType Directory -Force | Out-Null
        }

        try {
            $gpo = Get-GPO -All -ErrorAction Stop |
                   Where-Object { $_.DisplayName -like '*Banner*' } |
                   Select-Object -First 1
        } catch {
            return  # Do absolutely nothing if GPO query fails
        }

        if (-not $gpo) { return }  # No matching GPO => do nothing

        try {
            Get-GPOReport -Guid $gpo.Id -ReportType Xml -Path $tmpXml -ErrorAction Stop | Out-Null
            [xml]$BannerXML = Get-Content -Path $tmpXml -ErrorAction Stop
        } catch {
            if (Test-Path $tmpXml) { Remove-Item $tmpXml -Force -ErrorAction SilentlyContinue }
            return
        } finally {
            if (Test-Path $tmpXml) { Remove-Item $tmpXml -Force -ErrorAction SilentlyContinue }
        }

        # Try to extract values (guard against missing nodes)
        $displayText      = $BannerXML.gpo.computer.extensiondata.extension.policy.edittext.value
        $foregroundColor  = ($BannerXML.gpo.computer.extension.policy.dropdownlist.value)[1].name
        $backgroundColor  = ($BannerXML.gpo.computer.extension.policy.dropdownlist.value)[0].name

        if (-not $displayText -or -not $foregroundColor -or -not $backgroundColor) {
            return  # Missing expected values => do nothing
        }

        # Write cache
        @($displayText, $foregroundColor, $backgroundColor) | Set-Content -Path $cacheFile -Encoding UTF8
    }

    # Read cached banner info
    $bannerContent = Get-Content -Path $cacheFile -ErrorAction SilentlyContinue
    if (-not $bannerContent -or $bannerContent.Count -lt 3) { return }

    $width  = [console]::WindowWidth
    $status = $bannerContent[0]

    $leftPadding = [math]::Max(0, ($width - $status.Length) / 2)
    $line = (" " * [math]::Floor($leftPadding)) + $status
    $line = $line.PadRight($width)

    # Background color normalization: "Dark" + ColorName (only if not already "DarkX")
    $bgName = $bannerContent[2].ToString()
    if ($bgName -notmatch '^Dark') { $bgName = "Dark$bgName" }

    try {
        Write-Host $line -BackgroundColor $bgName -ForegroundColor $bannerContent[1]
    } catch {
        return  # If colors are invalid => do nothing
    }
}