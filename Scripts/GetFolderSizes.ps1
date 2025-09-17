param(
		[Parameter(Position=0, ValueFromPipeline=$True, Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[System.String]
		$Path
	)

function Get-FolderSize ($_ = (get-item .))  {
  Process {
    $ErrorActionPreference = "SilentlyContinue"
    $length = (Get-ChildItem $_.fullname -recurse | Measure-Object -property length -sum).sum
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Folder ($_.FullName)
    $obj | Add-Member NoteProperty Length ($length)
     Write-Output $obj
  }
}

Function Class-Size($size)
{

  IF($size -ge 1GB)
   {
      "{0:n2}" -f  ($size / 1GB) + " GigaBytes"
   }
 ELSEIF($size -ge 1MB)
    {
      "{0:n2}" -f  ($size / 1MB) + " MegaBytes"
    }
 ELSE
    {
      "{0:n2}" -f  ($size / 1KB) + " KiloBytes"
    }
} 
 
   

Get-ChildItem $Path | Get-FolderSize | Sort-Object -Property Length -Descending | Select-Object -Property Folder, Length |
Format-Table -Property Folder, @{ Label="Size of Folder" ; Expression = {Class-Size($_.Length)} }