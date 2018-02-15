$Path = "C:\nessusdata\"
    $thisMonth = (Get-Date).ToString("MMMyyyy")
    $zippy = [string]::Concat($path,"NSOC\",$thisMonth,".zip")

    $status = test-path "c:\nessusdata\NSOC\$thisMonth.zip"

    Write-host "Checking for updates...  The Script will start once the updates are detected"

    while ($status -eq $False) {
        write-host"."
        $status = test-path "c:\nessusdata\NSOC\$thisMonth.zip"
    
        if ($status -eq $True) {
            write-host "Updates Found Starting now..."
            $status = test-path "c:\nessusdata\NSOC\$thisMonth.zip"
                    break
        } 
    }
