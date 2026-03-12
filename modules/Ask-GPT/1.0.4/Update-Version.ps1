# Version Management Script for Ask-GPT Module
# Usage: ./Update-Version.ps1 -NewVersion "1.1.0" -ReleaseNotes "Bug fixes and improvements"

param(
    [Parameter(Mandatory=$true)]
    [string]$NewVersion,
    
    [Parameter(Mandatory=$false)]
    [string]$ReleaseNotes = "Version update"
)

# Validate version format (semantic versioning)
if ($NewVersion -notmatch '^\d+\.\d+\.\d+$') {
    Write-Error "Version must be in semantic versioning format (e.g., 1.0.0)"
    exit 1
}

Write-Host "Updating Ask-GPT module to version $NewVersion..." -ForegroundColor Green

# Update module manifest
$manifestPath = "./Ask-GPT.psd1"
if (Test-Path $manifestPath) {
    $content = Get-Content $manifestPath -Raw
    $content = $content -replace "ModuleVersion = '[^']*'", "ModuleVersion = '$NewVersion'"
    $content = $content -replace "ReleaseNotes = '[^']*'", "ReleaseNotes = '$ReleaseNotes'"
    Set-Content $manifestPath -Value $content -NoNewline
    Write-Host "✓ Updated module manifest version" -ForegroundColor Green
} else {
    Write-Error "Module manifest not found at $manifestPath"
    exit 1
}

# Update changelog
$changelogPath = "./CHANGELOG.md"
if (Test-Path $changelogPath) {
    $changelogContent = Get-Content $changelogPath -Raw
    $date = Get-Date -Format "yyyy-MM-dd"
    $newEntry = "## [$NewVersion] - $date`n`n### Changed`n- $ReleaseNotes`n`n"
    $changelogContent = $changelogContent -replace "## \[Unreleased\]", "## [Unreleased]`n`n$newEntry"
    Set-Content $changelogPath -Value $changelogContent -NoNewline
    Write-Host "✓ Updated changelog" -ForegroundColor Green
} else {
    Write-Warning "Changelog not found at $changelogPath"
}

# Validate the module after version update
Write-Host "Validating updated module..." -ForegroundColor Yellow
try {
    Test-ModuleManifest $manifestPath -ErrorAction Stop
    Write-Host "✓ Module manifest validation passed" -ForegroundColor Green
} catch {
    Write-Error "Module manifest validation failed: $_"
    exit 1
}

# Run PSScriptAnalyzer if available
if (Get-Module -ListAvailable PSScriptAnalyzer) {
    Write-Host "Running PSScriptAnalyzer..." -ForegroundColor Yellow
    $analysisResults = Invoke-ScriptAnalyzer -Path "./Ask-GPT.psm1" -Severity Warning,Error
    if ($analysisResults.Count -eq 0) {
        Write-Host "✓ PSScriptAnalyzer passed" -ForegroundColor Green
    } else {
        Write-Warning "PSScriptAnalyzer found issues:"
        $analysisResults | Format-Table
    }
}

Write-Host "`nVersion update complete!" -ForegroundColor Green
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Review the changes in git" -ForegroundColor White
Write-Host "2. Commit the version bump: git add . && git commit -m 'Version $NewVersion'" -ForegroundColor White
Write-Host "3. Tag the release: git tag -a v$NewVersion -m 'Release $NewVersion'" -ForegroundColor White
Write-Host "4. Push changes: git push && git push --tags" -ForegroundColor White
Write-Host "5. Consider publishing to PowerShell Gallery" -ForegroundColor White
