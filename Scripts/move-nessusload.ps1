$topDir = "c:\nessusdata"
$logDir = [string]::Concat($topDir,"\logs")
$logFile = [string]::Concat($logDir,"\",$timeStamp.log)
$nsocDir = [string]::Concat($topDir,"\NSOC")
$lastMonth = (Get-Date).AddMonths(-1).ToString("MMMyyyy")
$thisMonth = (Get-Date).ToString("MMMyyyy")
$timeStamp = (get-date).ToString("yyyyMMddHHmmss")
$thisMonthPath = [string]::Concat($nsocDir,"\",$thisMonth)
$lastMonthPath = [string]::Concat($nsocDir,"\",$lastMonth)

 
$destDirA = [string]::Concat($topDir,"\cm1\connector.remote.nessusV2Compliance\new")
$destDirB = [string]::Concat($topDir,"\cm2\connector.remote.nessusV2Compliance\new")
$destDirC = [string]::Concat($topDir,"\cm3\connector.remote.nessusV2Compliance\new")
$destDirD = [string]::Concat($topDir,"\cm4\connector.remote.nessusV2Compliance\new")
$destDirE = [string]::Concat($topDir,"\cm5\connector.remote.nessusV2Compliance\new")
$destDirF = [string]::Concat($topDir,"\cm6\connector.remote.nessusV2Compliance\new")
#Mention the path to search the files

##Find out the files greater than equal to below mentioned size
$sizeOnehund = 100MB
$sizeTwohund = 200MB
$sizeThreehund = 300MB
$SizeFivehund = 500MB
$SizeOneGig = 1GB

##Limit the number of rows
$limit = 10000
##Find out the specific extension file
$Extension = "*.*"

#$folders = "$destDirA", "$destDirB", "$destdirC","$destdirD","$destDirE"
#$path = gci C:\nessusdata\cm*\*\* | ?{ $_.psiscontainer}


    get-ChildItem $thismonthpath -recurse -ErrorAction "SilentlyContinue" -include $Extension |
    where-Object { !($_.PSIsContainer) -and $_.Length -lt $SizeOneGig}

    ForEach-Object { 
        write-Output "$($_.fullname) -and $($_.Length / 999MB)"
                Copy-Item $_.fullname $destDirA

        Write-Output "$($_.fullname) $($_.Length / 9991Mb)"
                Copy-Item $_.fullname $destDirB

       Write-Output "$($_.fullname) $($_.Length / 9991Mb)"
                Copy-Item $_.fullname $destdirC

        Write-Output "$($_.fullname) $($_.Length / 999Mb)"
                Copy-Item $_.fullname $destDirD

        Write-Output "$($_.fullname) $($_.Length / 999Mb)"
                Copy-Item $_.fullname $destDirE

        Write-Output "$($_.fullname) $($_.Length / 999Mb)"
                Copy-Item $_.fullname $destDirF
    }







get-ChildItem $thismonthpath -recurse -ErrorAction "SilentlyContinue" -include $Extension | 
    Where-Object { !($_.PSIsContainer) -and $_.Length -lt $sizeOnehund} | 
    ForEach-Object{
            Write-Output "$($_.fullname) $($_.Length / 1Mb)"
            Copy-Item $_.fullname $destDirA
            
        Write-Output "$($_.fullname) $($_.Length / 1Mb)"
        Copy-Item $_.fullname $destDirB

         Write-Output "$($_.fullname) $($_.Length / 1Mb)"
        Copy-Item $_.fullname $destDirC

         Write-Output "$($_.fullname) $($_.Length / 1Mb)"
        Copy-Item $_.fullname $destDirD

         Write-Output "$($_.fullname) $($_.Length / 1Mb)"
        Copy-Item $_.fullname $destDirE

         Write-Output "$($_.fullname) $($_.Length / 1Mb)"
        Copy-Item $_.fullname $destDirF
        }

   
    get-ChildItem $thismonthpath -recurse -ErrorAction "SilentlyContinue" -include $Extension | 
    Where-Object { !($_.PSIsContainer) -and $_.Length -lt $sizetwohund } | 
    ForEach-Object {
        Write-Output "$($_.fullname) $($_.Length / 101Mb)"
        Copy-Item $_.fullname $destDirA

        Write-Output "$($_.fullname) $($_.Length / 101Mb)"
        Copy-Item $_.fullname $destDirB

         Write-Output "$($_.fullname) $($_.Length / 101Mb)"
        Copy-Item $_.fullname $destDirC

         Write-Output "$($_.fullname) $($_.Length / 101Mb)"
        Copy-Item $_.fullname $destDirD

         Write-Output "$($_.fullname) $($_.Length / 101Mb)"
        Copy-Item $_.fullname $destDirE

         Write-Output "$($_.fullname) $($_.Length / 101Mb)"
        Copy-Item $_.fullname $destDirF
        }
    }
}
    do{
        get-ChildItem $thismonthpath -recurse -ErrorAction "SilentlyContinue" -include $Extension | 
        Where-Object { !($_.PSIsContainer) -and $_.Length -lt $sizethreehund } | 
        ForEach-Object {
        Write-Output "$($_.fullname) $($_.Length / 201Mb)"
        Copy-Item $_.fullname $destDirA

         Write-Output "$($_.fullname) $($_.Length / 201Mb)"
        Copy-Item $_.fullname $destDirA

         Write-Output "$($_.fullname) $($_.Length / 201Mb)"
        Copy-Item $_.fullname $destDirC

         Write-Output "$($_.fullname) $($_.Length / 201Mb)"
        Copy-Item $_.fullname $destDirD

         Write-Output "$($_.fullname) $($_.Length / 201Mb)"
        Copy-Item $_.fullname $destDirE

         Write-Output "$($_.fullname) $($_.Length / 201Mb)"
        Copy-Item $_.fullname $destDirF
        }
    }