function prompt {
    #detect repo/branch
    banner
    $git = $null
    $path = $PWD.Path
    while ($path) {
        $head = Join-Path $path ".git\HEAD"
        if (Test-Path $head) {
            $repo = Split-Path $path -Leaf
            $line = [System.IO.File]::ReadLines($head) | Select-Object -First 1
            if ($line -match "refs/heads/(.+)") {
                $git = "$repo/$($matches[1])"
            }
            else {
                $git = $repo
            }
            break
        }
        $path = Split-Path $path
    }
    #path formatting
    $currentPath = (Get-Location).Path
    $shome = [Environment]::GetFolderPath('UserProfile')
    if ($currentPath -like "$shome*") {
        $currentPath = "~" + $currentPath.Substring($shome.Length) -replace '\\','/'
    }
    else {
        $currentPath = $currentPath -replace '\\','/'
    }
    #admin detection
    $isAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    #prompt
    Write-Host "[" -ForegroundColor DarkYellow -NoNewline
    if ($git) {
        Write-Host "repo:$git " -ForegroundColor Magenta -NoNewline
    }
    Write-Host "$env:USERNAME@$env:COMPUTERNAME " -ForegroundColor Cyan -NoNewline
    if ($isAdmin) {
        Write-Host "ADMIN" -ForegroundColor Red -NoNewline
    }
    if ($PSVersionTable.PSVersion.Major -eq 7) {
        Write-Host " PS7" -ForegroundColor DarkCyan -NoNewline
    }
    Write-Host " $currentPath]" -ForegroundColor DarkYellow -NoNewline
    Write-Host "$ " -ForegroundColor DarkYellow -NoNewline
    return " "
}