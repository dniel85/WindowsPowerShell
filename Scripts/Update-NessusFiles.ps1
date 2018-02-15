Write-host "Checking for updates...  The Script will start once the updates are detected"

workflow Update-NessusFiles {
    InlineScript{
        $Path = "C:\nessusdata\"
            $thisMonth = (Get-Date).ToString("MMMyyyy")
            $zippy = [string]::Concat($path,"NSOC\",$thisMonth,".zip")

            $status = test-path "c:\nessusdata\NSOC\$thisMonth.zip"


            while ($status -eq $False) {
                
                $status = test-path "c:\nessusdata\NSOC\$thisMonth.zip"
            
                if ($status -eq $True) {
                
                    $status = test-path "c:\nessusdata\NSOC\$thisMonth.zip"
                            break
                } 
            }
    }
    
    InlineScript{c:\Users\darrell.nielsen\Documents\WindowsPowerShell\scripts\Move-NessusFiles.ps1}
    }

workflow Migrate-NessusFiles{
    parallel {
            
            InlineScript { C:\Users\darrell.nielsen\Documents\WindowsPowerShell\scripts\nessusConnectors\cm1Move.ps1}   
            InlineScript { C:\Users\darrell.nielsen\Documents\WindowsPowerShell\scripts\nessusConnectors\cm2Move.ps1}
            InlineScript { C:\Users\darrell.nielsen\Documents\WindowsPowerShell\scripts\nessusConnectors\cm3Move.ps1}
            InlineScript { C:\Users\darrell.nielsen\Documents\WindowsPowerShell\scripts\nessusConnectors\cm4Move.ps1}
            InlineScript { C:\Users\darrell.nielsen\Documents\WindowsPowerShell\scripts\nessusConnectors\cm5Move.ps1}
            InlineScript { C:\Users\darrell.nielsen\Documents\WindowsPowerShell\scripts\nessusConnectors\cm6Move.ps1}
        }
    }
update-NessusFiles
Migrate-NessusFiles


Write-host "finishing up..."

Write-host "Migrating update Files"
set-location -path "c:\nessusdata\NSOC"

Move-Item -Path [string]$thisMonth -Destination $topDir\oldDir -Force
    get-childitem -path "c:\nessusdata\oldDir" |
    where-object {$_.LastWriteTime -lt (get-date).Adddays(-30)} |
        remove-item


$destDirA = "$topDir\cm1\connector.remote.nessusV2Compliance\new"
$destDirB = "$topDir\cm2\connector.remote.nessusV2Compliance\new"
$destDirC = "$topDir\cm3\connector.remote.nessusV2Compliance\new"
$destDirD = "$topDir\cm4\connector.remote.nessusV2Compliance\new"
$destDirE = "$topDir\cm5\connector.remote.nessusV2Compliance\new"
$destDirF = "$topDir\cm6\connector.remote.nessusV2Compliance\new"
  

get-childitem -Path $destDirA, $destDirB, $destDirC, $destDirD, $destDirE, $destdirF |
  where-object {$_.LastWriteTime -lt (get-date).AddMinnute(-3)} |
  move-item -destination "c:\nessusdata\archiveDir"


set-location -path "c:\Users\darrell.nielsen\Documents\WindowsPowerShell\scripts"  #or wherever you have them saved
  .\update-NessusFiles.ps1  

