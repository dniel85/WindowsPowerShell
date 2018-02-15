
$topDir = "c:\nessusdata"

##Find out the files greater than equal to below mentioned size
#$sizeOnehund = 100MB
#$sizeTwohund = 200MB
#$sizeThreehund = 300MB
#$SizeFivehund = 500MB


##Find out the specific extension file
$nsocDir = [string]::Concat($topDir,"\NSOC")

$thisMonth = (Get-Date).ToString("MMMyyyy")
$thisMonthPath = [string]::Concat($nsocDir,"\",$thisMonth)
$Extension = "*.*"
$SizeOneGig = 1GB
$destDirE = [string]::Concat($topDir,"\cm5\connector.remote.nessusV2Compliance\new")

get-ChildItem $thismonthpath -recurse -ErrorAction "SilentlyContinue" -include $Extension | 
    Where-Object { !($_.PSIsContainer) -and $_.Length -lt $SizeOneGig} | 
    ForEach-Object{
            Write-Output "$($_.fullname) $($_.Length / 1Mb)"
                        Copy-Item $_.fullname $destDirE
    }
       