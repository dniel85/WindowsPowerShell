#EXAMPLE:
# .\Create-DummyFiles.ps1 -amount 20000 -size 50kb -folder 'F:\Temp\createfiles'




param(
$amount = $(throw "Please give an amount of files to be created")
, $size = $(throw "Please give a the size of the files")
, $folder = $(throw "Please give an output folder wehere the files need to be created")
, $name = $null
, $extension = $null
)
CLS
# Check for input
if(Test-Path $folder)
{
if($name -eq $null)
{
Write-Host "No filename given. Using default setting 'dummy'" -ForegroundColor Yellow
$name = 'dummy'
}
 
if($extension -eq $null)
{
Write-Host "No filename extension given. Using default setting 'nessus'" -ForegroundColor Yellow
$extension = 'nessus'
}
elseif($extension -contains '.')
{
$extension = $extension.Substring(($extension.LastIndexOf(".") + 1), ($extension.Length - 1))
}
 
for($i = 1; $i -le $amount; $i++)
{
$path = $folder + '\' + $name + '_' + $i + '.' + $extension
$file = [io.file]::Create($path)
$file.SetLength($size)
$file.Close
sleep 0.5
}
 
}
else{
Write-Host "The folder $folder doesn't exist" -ForegroundColor Red
Exit(0)
}