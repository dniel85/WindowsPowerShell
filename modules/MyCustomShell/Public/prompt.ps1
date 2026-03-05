function prompt {
    $currentPath = (Get-Location).Path
    $shome = [Environment]::GetFolderPath('UserProfile')
    if ($currentPath -like "$shome*") {
        $currentPath = "~" + $currentPath.Substring($shome.Length) -replace '\\','/'
    }
    else {
        $currentPath = $currentPath -replace '\\','/'
    }
    $isAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Host "[" -ForegroundColor DarkYellow -NoNewline
    Write-Host "$env:USERNAME@$env:COMPUTERNAME " -ForegroundColor Cyan -NoNewline
    if ($isAdmin) {
        Write-Host "ADMIN" -ForegroundColor Red -NoNewline
    }
    if($PSVersionTable.PSVersion.Major -eq 7){
        write-host " PS7" -ForegroundColor DarkCyan -nonewline
    }
    Write-Host " $currentPath]" -ForegroundColor DarkYellow -NoNewline
    Write-Host "$ " -ForegroundColor DarkYellow -NoNewline
    return " "
}