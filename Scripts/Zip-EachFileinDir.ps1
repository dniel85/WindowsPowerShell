#requires -version 5
$files = get-childitem 'C:\users\xadministrator\Desktop\test folder'
foreach($file in $files){
$zipfilename = $file.fullname + ".zip"
Compress-Archive -LiteralPath $file.FullName -CompressionLevel Optimal -DestinationPath ($file.FullName + ".zip")
}