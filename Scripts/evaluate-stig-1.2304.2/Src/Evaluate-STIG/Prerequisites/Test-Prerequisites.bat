::::::::::::::::::::::::::::::::::::::::::
:: Automatcially check & get admin rights
::::::::::::::::::::::::::::::::::::::::::
@echo off
CLS
ECHO.
ECHO =====================================
ECHO Running Admin shell
ECHO =====================================

:init
setlocal DisableDelayedExpansion
set "batchPath=%~0"
for %%k in (%0) do set batchName=%%~nk
set "vbsGetPrivileges=%temp%\OEgetPriv_%batchName%.vbs"
setlocal EnableDelayedExpansion

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%'=='0' (goto gotPrivileges) else (goto getPrivileges)

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)
ECHO.
ECHO *************************************
ECHO Invoking UAC for Privilege Escalation
ECHO *************************************

ECHO Set UAC = CreateObject^("Shell.Application"^) > %vbsGetPrivileges%"
ECHO args = "ELEV " >> "%vbsGetPrivileges%"
ECHO For Each strArg in WScript.Arguments >> "%vbsGetPrivileges%"
ECHO args = args ^& strArg ^& " " >> "%vbsGetPrivileges%"
ECHO Next >> "%vbsGetPrivileges%"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%vbsGetPrivileges%"
"%SystemRoot%\System32\WScript.exe" "%vbsGetPrivileges%" %*
exit /B

:gotPrivileges
setlocal & pushd .
cd /d %~dp0
if '%1'=='ELEV' (del "%vbsGetPrivileges%" 1>nul 2>nul & shift /1)

::::::::::::::::::::::::::::::::::::::::::
:: START
::::::::::::::::::::::::::::::::::::::::::
ECHO.
ECHO Checking certificates...
REM Check for DoD Root CA 3 certificate
PowerShell.exe -Command "Try {If (Get-ChildItem Cert:\LocalMachine\Root | Where-Object Thumbprint -eq 'D73CA91102A2204A36459ED32213B467D7CE97FB') {Write-Host 'DoD Root CA 3 : Imported (Local Machine\Root)' -ForegroundColor Green} Else {Write-Host 'DoD Root CA 3 : Not imported (Local Machine\Root)' -ForegroundColor Yellow}} Catch {Write-Host $_.Exception.Message -ForegroundColor Red}"

REM Check for DOD ID CA-59 certificate
PowerShell.exe -Command "Try {If (Get-ChildItem Cert:\LocalMachine\CA | Where-Object Thumbprint -eq '1907FC2B223EE0301B45745BDB59AAD90FE7C5D7') {Write-Host 'DOD ID CA-59  : Imported (Local Machine\CA)' -ForegroundColor Green} Else {Write-Host 'DOD ID CA-59  : Not imported (Local Machine\CA)' -ForegroundColor Yellow}} Catch {Write-Host $_.Exception.Message -ForegroundColor Red}"

REM Check for CS.NSWCCD.001 certificate
PowerShell.exe -Command "Try {If (Get-ChildItem Cert:\LocalMachine\TrustedPublisher | Where-Object Thumbprint -eq 'D95F944E33528DC23BEE8672D6D38DA35E6F0017') {Write-Host 'CS.NSWCCD.001 : Imported (Local Machine\Trusted Publishers)' -ForegroundColor Green} Else {Write-Host 'CS.NSWCCD.001 : Not imported (Local Machine\Trusted Publishers)' -ForegroundColor Yellow}} Catch {Write-Host $_.Exception.Message -ForegroundColor Red}"

REM Check PowerShell execution policy (cannot be "Restricted")
ECHO.
ECHO Checking PowerShell execution policy...
PowerShell.exe -Command "Try {$ExecPol=Get-ExecutionPolicy; If ($ExecPol -ne 'Restricted') {Write-Host 'Execution Policy : '$ExecPol' (Supported)' -ForegroundColor Green} Else {Write-Host 'Execution Policy : '$ExecPol' (Not supported)' -ForegroundColor Yellow; Write-Host ''; Write-Host 'PowerShell execution policy cannot be set to Restricted.  Please change with Set-ExecutionPolicy command.' -ForegroundColor Yellow; Write-Host 'Supported execution policies include AllSigned, RemoteSigned, or Unrestricted' -ForegroundColor Yellow}} Catch {Write-Host $_.Exception.Message -ForegroundColor Red}"

ECHO.
ECHO.
Pause