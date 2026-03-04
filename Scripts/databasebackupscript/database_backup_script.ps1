<#
.SYNOPSIS
Automated Backup script with custom folder structure with weekly/monthly rotation. 
#>

$scriptName = ($MyInvocation.MyCommand).Name.replace('.ps1','.log').ToString()
$logPath = join-path $PSScriptRoot $scriptName
if(-not(test-path $logPath)){new-Item -path }
Start-Transcript -Path $logPath -Append 

#-------------------------------------------Configuration ---------------------------------------------
$backupRoot = "G:\Database_backups"
$weeksToKeep = 4
$monthsToKeep = 2
$sqlCmdExpectedPath = Join-Path $PSScriptRoot "sqlcmd-amd64.msi" -ErrorAction silentlycontinue

#-------------------------------------- Check for sqlcmd ------------------------------------------

$sqlcmd = get-command sqlcmd -ErrorAction SilentlyContinue

if(-not $sqlcmd){
    Write-Host "sqlcmd.exe is NOT installed on this system." -ForegroundColor Red

    if(Test-Path $sqlCmdExpectedPath) {
        Write-Host "You can install sqlcmd from the file located at: `n$sqlCmdExpectedPath" -ForegroundColor Yellow
    }
    else{ 
        Write-Host "sqlcmd.exe was not found in the script directory ($PSScriptRoot). `nsqlcmd.msi can be installed from the official Microsoft github repository at: `n `
        github.com/microsoft/go-sqlcmd/releases" -ForegroundColor Cyan 
        }
    exit 1 
    }



#----------------------------- Get databases dynamically ---------------------------------------------
if((Get-Service *ssql*).name -Like "*##WID*"){
        $DB_Connection = "np:\\.\pipe\Microsoft##WID\tsql\query"
        }
    if((Get-Service *ssql*).name -Like "*MSSQLSERVER*"){
        $DB_Connection = $env:COMPUTERNAME
        }
    if((Get-Service *ssql*).name -Like "*SQLEXPRESS*"){
        $DB_Connection = "$env:COMPUTERNAME\SQLEXPRESS"
        }

$DATABASES = sqlcmd -S $DB_Connection -h -1 -W -Q "SET NOCOUNT ON; SELECT NAME FROM sys.databases WHERE NAME NOT IN ('master','tempdb','model','msdb')"
    if($DB_Connection -like "*WID*"){
        $databases=$databases[0..($databases.Count -2)]
        }

#------------------------------Backup loop --------------------------------------------------------

foreach($db in $DATABASES){
    $dbFolder = Join-Path $backupRoot $db
    if(-not (Test-Path $dbFolder)) {New-Item -Path $dbFolder -ItemType Directory |Out-Null}

    $weeklyFolder = Join-Path $dbFolder "Weekly"
    $monthlyFolder = Join-Path $dbFolder "Monthly"

    foreach($folder in @($weeklyFolder, $monthlyFolder)){
        if(-not(Test-Path $folder)){New-Item -Path $folder -ItemType Directory | Out-Null}
    }

    $weeklyDate = get-date -Format "dd_MM"
    $monthlyDate = get-date -Format "MM_yyy"

    $weeklyBackupFile = Join-Path $weeklyFolder "$db-$weeklyDate.bak"
    $monthlyBackupFile = Join-Path $monthlyFolder "$db-$monthlyDate.bak"
    if((get-date).DayOfWeek -eq "Wednesday"){
        try{
            sqlcmd -S $DB_Connection -Q "BACKUP DATABASE [$db] TO DISK=N'$weeklyBackupFile' WITH INIT, COMPRESSION"
            Write-Host "Weekly backup Created: $weeklyBackupFile"
        }catch{
        Write-Error "$db : $_"
        }
    }
    if((get-date).Day -eq 1){
        try{
            sqlcmd -S $DB_Connection -Q "BACKUP DATABASE [$db] TO DISK=N'$monthlyBackupFile' WITH INIT, COMPRESSION"
            Write-Host "Mothly Backup created: $monthlyBackupFile"
        }catch{
            Write-Error "$db : $_"
        }
    }
#------------------------------------------------------------- Backup Rotation ----------------------------------------------------------------------

    Get-ChildItem $weeklyFolder -Filter "*.bak" | Sort-Object CreationTime -Descending | Select-Object -Skip $weeksToKeep | Remove-Item -Force -ErrorAction SilentlyContinue

    Get-ChildItem $monthlyFolder -Filter "*.bak" | Sort-Object CreationTime -Descending | Select-Object -Skip $monthsToKeep | Remove-Item -Force -ErrorAction SilentlyContinue
}


Stop-Transcript