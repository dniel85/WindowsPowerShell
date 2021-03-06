﻿function Encrypt-Data
{
Add-Type -Assembly System.Security 
Add-Type -AssemblyName System.Windows.Forms 
 
$FileBrowser = New-Object system.windows.forms.openfiledialog 
$FileBrowser.InitialDirectory = $PSScriptRoot 
$FileBrowser.MultiSelect = $false 
$FileBrowser.showdialog() | Out-Null 
$file = $FileBrowser.FileName 
 
function EncryptData($string){ 
 
    if(Test-Path $file) 
    { 
    Write-Host $file 
        try{ 
        $string = gc $file -Raw  
        Write-Host "File succesfully imported" -ForegroundColor Green 
        } 
        catch{ 
     
        } 
    } 
    else 
    { 
    Write-Host "File $($file) not found" -ForegroundColor Red 
    exit 
    } 
 
$bytes = $string.ToCharArray() | % {[byte] $_} 
 
# Encrypts the byte array. 
 
$encryptedBytes = [System.Security.Cryptography.ProtectedData]::Protect($bytes,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser) > $file 
Write-Host "Encrypted Data" -ForegroundColor Cyan 
Write-Host ([string] $encryptedBytes) -ForegroundColor DarkGreen 
} 
 
EncryptData($string) 
Write-Host "Press any key to exit..." 
 
$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") 
}

function Decrypt-Data
{
Add-Type -Assembly System.Security 
Add-Type -AssemblyName System.Windows.Forms 
 
$FileBrowser = New-Object system.windows.forms.openfiledialog 
$FileBrowser.InitialDirectory = $PSScriptRoot 
$FileBrowser.MultiSelect = $false 
$FileBrowser.showdialog() | Out-Null 
$file = $FileBrowser.FileName 
 
function DecryptData($string) 
{ 
    if(Test-Path $file) 
    { 
        try{ 
        $string = gc $file 
        Write-Host "File $($file) succesfully imported" -ForegroundColor Green 
        } 
        catch{ 
     
        } 
    } 
    else 
    { 
    Write-Host "File $($file) not found" -ForegroundColor Red 
    exit 
    } 
# Unencrypt the data. 
    try{ 
    $bytes2 = [System.Security.Cryptography.ProtectedData]::Unprotect($string,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser) 
    $bytes2 | % { $clearText += [char] $_} 
 
    Write-Host "Decrypted Data" -ForegroundColor Cyan 
    $clearText > $file 
    } 
    catch{ 
    Write-Host "Error" -ForegroundColor Red 
    } 
} 
 
DecryptData($string) 
 
Write-Host "Press any key to exit ..." 
 
$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") 
}