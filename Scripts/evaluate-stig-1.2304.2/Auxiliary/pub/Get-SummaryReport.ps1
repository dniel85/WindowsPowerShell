<#
    .Synopsis
    Create an Report from completed STIG assessments.
    .DESCRIPTION
    Creates a report from Evaluate-STIG Summary Reports.  Suggest running Validate-Results.ps1 prior to creating this report.
    Excel is required be installed.
    .EXAMPLE
    PS C:\> Get-SummaryReport.ps1 -ESResultsPath C:\Results
    .INPUTS
    -ESResultsPath
        Path to the Evaluate-STIG results directory.  Expected structure - Results Directory -> HostName Directory -> Checklist Directory, SummaryReport.xml
    .INPUTS
    -MachineInfo
        Add a worksheet for per Machine findings (increases run time substantially).
    .INPUTS
    -STIGInfo
        Add worksheets for each STIG found in Summary Reports (increases run time substantially).
    .INPUTS
    -OutputPath
        Path to location to save Summary Report.
#>

Param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String[]]$ESResultsPath,

    [Parameter(Mandatory = $false)]
    [switch]$MachineInfo,

    [Parameter(Mandatory = $false)]
    [switch]$STIGInfo,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [String]$OutPutpath
)

Function Write-Log {
    <#
    .Synopsis
        Write to a CMTrace friendly .log file.
    .DESCRIPTION
        Takes the input and generates an entry for a CMTrace friendly .log file
        by utilizing a PSCustomObject and Generic List to hold the data.
        A string is created and added to the .log file.
    .EXAMPLE
       PS C:\> Write-Log -Path 'C:\Temp\sample.log' -Message 'Test Message' -Component 'Write-Log' -MessageType Verbose -OSPlatform Windows
    .INPUTS
        -Path
            Use of this parameter is required. Forced to be a String type. The path to where the .log file is located.
        -Message
            Use of this parameter is required. Forced to be a String type. The message to pass to the .log file.
        -Component
            Use of this parameter is required. Forced to be a String type. What is providing the Message.
            Typically this is the script or function name.
        -Type
            Use of this parameter is required. Forced to be a String type. What type of output to be. Choices are
            Info, Warning, Error and Verbose.
        -OSPlatform
            Use of this parameter is required. Forced to be a String type. What OS platform the system is. Choices are Windows or Linux.
    .OUTPUTS
        No output. Writes an entry to a .log file via Add-Content.
    .NOTES
        Resources/Credits:
            Dan Ireland - daniel.ireland@navy.mil
            Brent Betts - brent.betts@navy.mil
        Helpful URLs:
            Russ Slaten's Blog Post - Logging in CMTrace format from PowerShell
            https://blogs.msdn.microsoft.com/rslaten/2014/07/28/logging-in-cmtrace-format-from-powershell/
    #>

    Param (
        [Parameter(Mandatory = $true)]
        [String]$Path,

        [Parameter(Mandatory = $true)]
        [String]$Message,

        [Parameter(Mandatory = $true)]
        [String]$Component,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Info", "Warning", "Error", "Verbose")]
        [String]$Type
    )

    # Obtain date/time

    $DateTime = New-Object -ComObject WbemScripting.SWbemDateTime
    $DateTime.SetVarDate($(Get-Date))
    $UtcValue = $DateTime.Value
    $UtcOffset = [Math]::Abs($UtcValue.Substring(21, $UtcValue.Length - 21))

    # Create Object to hold items to log
    $LogItems = New-Object System.Collections.Generic.List[System.Object]
    $NewObj = [PSCustomObject]@{
        Message   = $Message
        Time      = [Char]34 + (Get-Date -Format "HH:mm:ss.fff") + "+$UtcOffset" + [Char]34
        Date      = [Char]34 + (Get-Date -Format "MM-dd-yyyy") + [Char]34
        Component = [Char]34 + $Component + [Char]34
        Type      = [Char]34 + $Type + [Char]34
    }
    $LogItems.Add($NewObj)

    # Format Log Entry
    $Entry = "<![LOG[$($LogItems.Message)]LOG]!><time=$($LogItems.Time) date=$($LogItems.Date) component=$($LogItems.Component) type=$($LogItems.Type)"

    # Add to Log
    Add-Content -Path $Path -Value $Entry -ErrorAction SilentlyContinue | Out-Null
}

if (!($OutPutpath)){
    $OutPutpath = $PSScriptRoot
}

if (!($STIGInfo)){
    $STIGInfo = $false
}

$LogPath = "$OutPutPath\Summary_Report_Log_$(Get-Date -Format yyyyMMdd_hhmmss).log"
$Report_Name = "Summary_Report_$(Get-Date -Format yyyyMMdd_hhmmss).xlsx"

Write-Log $LogPath "==========[Begin Logging]==========" "PreReq_Check" "Info"

Try {
    $ReportExcel = New-Object -ComObject Excel.Application
}
Catch {
    Write-Host "Excel is not installed. Exiting" -ForegroundColor Red
    Write-Log $LogPath "Excel is not installed." "PreReq_Check" "Error"
    Write-Log $LogPath "==========[End Logging]==========" "PreReq_Check" "Info"
    return
}

Write-Host "Getting CKL data..."
Write-Log $LogPath "Getting CKL data..." "PreReq_Check" "Info"

$SummaryReports = New-Object -TypeName "System.Collections.ArrayList"
$SummaryReports = [System.Collections.ArrayList]@()
$Computer_count = New-Object -TypeName "System.Collections.ArrayList"
$Computer_count = [System.Collections.ArrayList]@()
$Findings_List = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$Counts_CAT_I = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$Counts_CAT_II = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$Counts_CAT_III = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

$null = $ESResultsPath | ForEach-Object { $SummaryReports += @(Get-ChildItem -Path $_ -Recurse -Filter "SummaryReport.xml" -File) | Where-Object { $_.FullName -notmatch "Previous" } }

if ($SummaryReports.Count -eq 0){
    Write-Host "No Summary Reports found.  Exiting." -ForegroundColor Red
    Write-Log $LogPath "No Summary Report found.  Exiting." "PreReq_Check" "Info"
    Write-Log $LogPath "==========[End Logging]==========" "PreReq_Check" "Info"
    return
}

$Summary_ScriptBlock = {
    param([xml]$SummaryXML, $Findings_List, $Counts_CAT_I, $Counts_CAT_II, $Counts_CAT_III, $Computer_count, $STIGInfo)

    ForEach ($Checklist in $SummaryXML.Summary.Checklists.Checklist) {
        if ($STIGInfo){
            $TempPath = [System.IO.Path]::GetTempPath() + $Checklist.STIG + ".csv"
            [System.Threading.Monitor]::Enter($Findings_List.SyncRoot)
            $Findings_List.Add($TempPath)
            [System.Threading.Monitor]::Exit($Findings_List.SyncRoot)
        }
        $findings = New-Object -TypeName "System.Collections.ArrayList"
        $findings_CAT_I = New-Object -TypeName "System.Collections.ArrayList"
        $findings_CAT_II = New-Object -TypeName "System.Collections.ArrayList"
        $findings_CAT_III = New-Object -TypeName "System.Collections.ArrayList"
        $findings = [System.Collections.ArrayList]@()
        $findings_CAT_I = [System.Collections.ArrayList]@()
        $findings_CAT_II = [System.Collections.ArrayList]@()
        $findings_CAT_III = [System.Collections.ArrayList]@()

        $Computer_count.add($SummaryXML.Summary.Computer.Name)

        [System.Threading.Monitor]::Enter($Counts_CAT_I.SyncRoot)
        $Counts_CAT_I.Add([PSCustomObject]@{
            STIG           = $Checklist.STIG
            Hostname       = $SummaryXML.Summary.Computer.Name
            Total          = $Checklist.CAT_I.Total
            Open           = $Checklist.CAT_I.Open
            Not_Applicable = $Checklist.CAT_I.Not_Applicable
            NotAFinding    = $Checklist.CAT_I.NotAFinding
            Not_Reviewed   = $Checklist.CAT_I.NotReviewed
        })
        [System.Threading.Monitor]::Exit($Counts_CAT_I.SyncRoot)

        [System.Threading.Monitor]::Enter($Counts_CAT_II.SyncRoot)
        $Counts_CAT_II.Add([PSCustomObject]@{
                STIG           = $Checklist.STIG
                Hostname       = $SummaryXML.Summary.Computer.Name
                Total          = $Checklist.CAT_II.Total
                Open           = $Checklist.CAT_II.Open
                Not_Applicable = $Checklist.CAT_II.Not_Applicable
                NotAFinding    = $Checklist.CAT_II.NotAFinding
                Not_Reviewed   = $Checklist.CAT_II.NotReviewed
            })
        [System.Threading.Monitor]::Exit($Counts_CAT_II.SyncRoot)

        [System.Threading.Monitor]::Enter($Counts_CAT_III.SyncRoot)
        $Counts_CAT_III.Add([PSCustomObject]@{
                STIG           = $Checklist.STIG
                Hostname       = $SummaryXML.Summary.Computer.Name
                Total          = $Checklist.CAT_III.Total
                Open           = $Checklist.CAT_III.Open
                Not_Applicable = $Checklist.CAT_III.Not_Applicable
                NotAFinding    = $Checklist.CAT_III.NotAFinding
                Not_Reviewed   = $Checklist.CAT_III.NotReviewed
            })
        [System.Threading.Monitor]::Exit($Counts_CAT_III.SyncRoot)

        ForEach ($Vuln in $Checklist.CAT_I.Vuln) {
            $findings_CAT_I.Add([PSCustomObject]@{
                CKLDate   = $Checklist.Date
                Hostname  = $SummaryXML.Summary.Computer.Name
                CKL       = $Checklist.CklFile
                Status    = $Vuln.Status
                Severity  = "CAT I"
                ID        = $Vuln.ID
                RuleTitle = $Vuln.RuleTitle
            })
        }

        ForEach ($Vuln in $Checklist.CAT_II.Vuln) {
                $findings_CAT_II.Add([PSCustomObject]@{
                CKLDate   = $Checklist.Date
                Hostname  = $SummaryXML.Summary.Computer.Name
                CKL       = $Checklist.CklFile
                Status    = $Vuln.Status
                Severity  = "CAT II"
                ID        = $Vuln.ID
                RuleTitle = $Vuln.RuleTitle
            })
        }

        ForEach ($Vuln in $Checklist.CAT_III.Vuln) {
                $findings_CAT_III.Add([PSCustomObject]@{
                CKLDate   = $Checklist.Date
                Hostname  = $SummaryXML.Summary.Computer.Name
                CKL       = $Checklist.CklFile
                Status    = $Vuln.Status
                Severity  = "CAT III"
                ID        = $Vuln.ID
                RuleTitle = $Vuln.RuleTitle
            })
        }

        $Findings = $findings_CAT_I + $findings_CAT_II + $findings_CAT_III
        if ($STIGInfo){
            $Findings | Export-Csv $TempPath -NoTypeInformation -Append
        }
    }
}

Write-Host "Generating data from Summary Reports..."
Write-Log $LogPath "Generating data from Summary Reports..." "Summary Reports" "Info"

$MaxThreads = 10
$RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
$RunspacePool.ApartmentState = "MTA"
$RunspacePool.Open()
$Jobs = @()

$Scandate = New-Object -TypeName "System.Collections.ArrayList"
$Scandate = [System.Collections.ArrayList]@()

$SummaryReports | ForEach-Object {

    $SummaryXML = New-Object -TypeName System.Xml.XmlDataDocument
    Try{
        $SummaryXML.Load($_.FullName)
        $null = $Scandate.Add([PSCustomObject]@{
                Hostname = $SummaryXML.Summary.Computer.Name
                ScanDate = $SummaryXML.Summary.Computer.ScanDate
            })
    }
    Catch{
        Write-Host "Error loading $($_.FullName)" -ForegroundColor Red
        Write-Log $LogPath "Error loading $($_.FullName)" "Summary Reports" "Error"
        Continue
    }

    $Job = [powershell]::Create().AddScript($Summary_ScriptBlock).AddArgument($SummaryXML).AddArgument($Findings_List).AddArgument($Counts_CAT_I).AddArgument($Counts_CAT_II).AddArgument($Counts_CAT_III).AddArgument($Computer_count).AddArgument($STIGInfo)
    $Job.RunspacePool = $RunspacePool
    $Jobs += [PSCustomObject]@{Runspace = $Job; Status = $Job.BeginInvoke()}
}

while ($Jobs.IsCompleted -contains $false) {
    Start-Sleep 1
}

foreach ($Job In $Jobs) {
    $null = $Job.Runspace.EndInvoke($Job.Status)
    $job.Runspace.Dispose()
}

$RunspacePool.Close()
$RunspacePool.Dispose()

$Findings_List = $Findings_List | Sort-Object -Unique

Write-Host "Creating Excel Data..."
Write-Log $LogPath "Creating Excel Data..." "Excel" "Info"

$ReportExcel.visible = $false
Start-Sleep 2

$Finding_CSV = 1
$ReportExcel.sheetsInNewWorkbook = $Findings_List.count + 3
$workbooks = $ReportExcel.Workbooks.Add()
$InfoWKST = $workbooks.Worksheets.Item($Finding_CSV)

Write-Log $LogPath "Adding Information Data..." "Information Worksheet" "Info"

$InfoWKST.Name = "Information"
$InfoWKST.Cells.Item(1, 3) = "STIG Information per Evaluate-STIG"
$InfoWKST.Cells.Item(1, 3).Font.Size = 18
$InfoWKST.Range("C1:F1").MergeCells = $true

$Computer_count = $Computer_count | Sort-Object -Unique
$InfoWKST.Cells.Item(2, 1) = "STIG Totals for $($Computer_count.count) Computer(s)"
$InfoWKST.Cells.Item(2, 1).Font.Size = 18
$InfoWKST.Cells.Item(2, 1).HorizontalAlignment = -4108

$InfoWKST.Cells.Item(4, 2) = ($Counts_CAT_I | Measure-Object Open -Sum).Sum
$InfoWKST.Cells.Item(4, 3) = ($Counts_CAT_I | Measure-Object Not_Reviewed -Sum).Sum
$InfoWKST.Cells.Item(4, 4) = ($Counts_CAT_I | Measure-Object NotAFinding -Sum).Sum
$InfoWKST.Cells.Item(4, 5) = ($Counts_CAT_I | Measure-Object Not_Applicable -Sum).Sum
$InfoWKST.Cells.Item(4, 6) = ($Counts_CAT_I | Measure-Object Open -Sum).Sum + ($Counts_CAT_I | Measure-Object Not_Reviewed -Sum).Sum
$InfoWKST.Cells.Item(4, 7) = ($Counts_CAT_I | Measure-Object Total -Sum).Sum - ($Counts_CAT_I | Measure-Object Not_Applicable -Sum).Sum

$InfoWKST.Cells.Item(5, 2) = ($Counts_CAT_II | Measure-Object Open -Sum).Sum
$InfoWKST.Cells.Item(5, 3) = ($Counts_CAT_II | Measure-Object Not_Reviewed -Sum).Sum
$InfoWKST.Cells.Item(5, 4) = ($Counts_CAT_II | Measure-Object NotAFinding -Sum).Sum
$InfoWKST.Cells.Item(5, 5) = ($Counts_CAT_II | Measure-Object Not_Applicable -Sum).Sum
$InfoWKST.Cells.Item(5, 6) = ($Counts_CAT_II | Measure-Object Open -Sum).Sum + ($Counts_CAT_II | Measure-Object Not_Reviewed -Sum).Sum
$InfoWKST.Cells.Item(5, 7) = ($Counts_CAT_II | Measure-Object Total -Sum).Sum - ($Counts_CAT_II | Measure-Object Not_Applicable -Sum).Sum

$InfoWKST.Cells.Item(6, 2) = ($Counts_CAT_III | Measure-Object Open -Sum).Sum
$InfoWKST.Cells.Item(6, 3) = ($Counts_CAT_III | Measure-Object Not_Reviewed -Sum).Sum
$InfoWKST.Cells.Item(6, 4) = ($Counts_CAT_III | Measure-Object NotAFinding -Sum).Sum
$InfoWKST.Cells.Item(6, 5) = ($Counts_CAT_III | Measure-Object Not_Applicable -Sum).Sum
$InfoWKST.Cells.Item(6, 6) = ($Counts_CAT_III | Measure-Object Open -Sum).Sum + ($Counts_CAT_III | Measure-Object Not_Reviewed -Sum).Sum
$InfoWKST.Cells.Item(6, 7) = ($Counts_CAT_III | Measure-Object Total -Sum).Sum - ($Counts_CAT_III | Measure-Object Not_Applicable -Sum).Sum

$InfoWKST.Cells.Item(8, 2) = "CAT I"
$InfoWKST.Cells.Item(8, 2).Font.Size = 18
$InfoWKST.Cells.Item(8, 2).HorizontalAlignment = -4108
$InfoWKST.Range("B8:E8").MergeCells = $true

$InfoWKST.Cells.Item(8, 9) = "CAT II"
$InfoWKST.Cells.Item(8, 9).Font.Size = 18
$InfoWKST.Cells.Item(8, 9).HorizontalAlignment = -4108
$InfoWKST.Range("I8:L8").MergeCells = $true

$InfoWKST.Cells.Item(8, 16) = "CAT III"
$InfoWKST.Cells.Item(8, 16).Font.Size = 18
$InfoWKST.Cells.Item(8, 16).HorizontalAlignment = -4108
$InfoWKST.Range("P8:S8").MergeCells = $true

$InfoWKST.Cells.Item(3, 2) = "Open"
$InfoWKST.Cells.Item(3, 3) = "Not_Reviewed"
$InfoWKST.Cells.Item(3, 4) = "NotAFinding"
$InfoWKST.Cells.Item(3, 5) = "Not_Applicable"
$InfoWKST.Cells.Item(3, 6) = "Total Open"
$InfoWKST.Cells.Item(3, 7) = "Possible"
$InfoWKST.Cells.Item(4, 1) = "CAT I"
$InfoWKST.Cells.Item(5, 1) = "CAT II"
$InfoWKST.Cells.Item(6, 1) = "CAT III"

$InfoWKST.Cells.Item(9, 2) = "Open"
$InfoWKST.Cells.Item(9, 3) = "Not_Reviewed"
$InfoWKST.Cells.Item(9, 4) = "NotAFinding"
$InfoWKST.Cells.Item(9, 5) = "Not_Applicable"
$InfoWKST.Cells.Item(9, 6) = "Total Open"
$InfoWKST.Cells.Item(9, 7) = "Possible"
$InfoWKST.Cells.Item(9, 9) = "Open"
$InfoWKST.Cells.Item(9, 10) = "Not_Reviewed"
$InfoWKST.Cells.Item(9, 11) = "NotAFinding"
$InfoWKST.Cells.Item(9, 12) = "Not_Applicable"
$InfoWKST.Cells.Item(9, 13) = "Total Open"
$InfoWKST.Cells.Item(9, 14) = "Possible"
$InfoWKST.Cells.Item(9, 16) = "Open"
$InfoWKST.Cells.Item(9, 17) = "Not_Reviewed"
$InfoWKST.Cells.Item(9, 18) = "NotAFinding"
$InfoWKST.Cells.Item(9, 19) = "Not_Applicable"
$InfoWKST.Cells.Item(9, 20) = "Total Open"
$InfoWKST.Cells.Item(9, 21) = "Possible"

$cellcount = 10
$count = 0
Write-Log $LogPath "Adding CAT I Data..." "Information Worksheet" "Info"
Foreach ($STIG in ($Counts_CAT_I.STIG | Where-Object {$_} | Sort-Object -Unique)) {

    Write-Progress -Activity "Counting CAT I Findings" -Status $STIG -PercentComplete ($count / @($Counts_CAT_I.STIG | Select-Object -Unique).count * 100)

    $InfoWKST.Cells.Item($cellcount, 1) = $STIG
    $InfoWKST.Cells.Item($cellcount, 2) = (($Counts_CAT_I | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Open -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 3) = (($Counts_CAT_I | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Not_Reviewed -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 4) = (($Counts_CAT_I | Where-Object { $_.STIG -eq $STIG }) | Measure-Object NotAFinding -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 5) = (($Counts_CAT_I | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Not_Applicable -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 6) = (($Counts_CAT_I | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Open -Sum).Sum + (($Counts_CAT_I | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Not_Reviewed -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 7) = (($Counts_CAT_I | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Total -Sum).Sum - (($Counts_CAT_I | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Not_Applicable -Sum).Sum
    $cellcount++
    $count++
}

Write-Progress -Activity "Counting CAT I Findings" -Completed

$cellcount = 10
$count = 0
Write-Log $LogPath "Adding CAT II Data..." "Information Worksheet" "Info"
Foreach ($STIG in ($Counts_CAT_II.STIG | Where-Object {$_} | Sort-Object -Unique)) {

    Write-Progress -Activity "Counting CAT II Findings" -Status $STIG -PercentComplete ($count / @($Counts_CAT_II.STIG | Select-Object -Unique).count * 100)

    $InfoWKST.Cells.Item($cellcount, 9) = (($Counts_CAT_II | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Open -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 10) = (($Counts_CAT_II | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Not_Reviewed -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 11) = (($Counts_CAT_II | Where-Object { $_.STIG -eq $STIG }) | Measure-Object NotAFinding -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 12) = (($Counts_CAT_II | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Not_Applicable -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 13) = (($Counts_CAT_II | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Open -Sum).Sum + (($Counts_CAT_II | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Not_Reviewed -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 14) = (($Counts_CAT_II | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Total -Sum).Sum - (($Counts_CAT_II | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Not_Applicable -Sum).Sum
    $cellcount++
    $count++
}

Write-Progress -Activity "Counting CAT II Findings" -Completed

$cellcount = 10
$count = 0
Write-Log $LogPath "Adding CAT III Data..." "Information Worksheet" "Info"
Foreach ($STIG in ($Counts_CAT_III.STIG | Where-Object {$_} | Sort-Object -Unique)) {

    Write-Progress -Activity "Counting CAT III Findings" -Status $STIG -PercentComplete ($count / @($Counts_CAT_III.STIG | Select-Object -Unique).count * 100)

    $InfoWKST.Cells.Item($cellcount, 16) = (($Counts_CAT_III | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Open -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 17) = (($Counts_CAT_III | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Not_Reviewed -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 18) = (($Counts_CAT_III | Where-Object { $_.STIG -eq $STIG }) | Measure-Object NotAFinding -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 19) = (($Counts_CAT_III | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Not_Applicable -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 20) = (($Counts_CAT_III | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Open -Sum).Sum + (($Counts_CAT_III | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Not_Reviewed -Sum).Sum
    $InfoWKST.Cells.Item($cellcount, 21) = (($Counts_CAT_III | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Total -Sum).Sum - (($Counts_CAT_III | Where-Object { $_.STIG -eq $STIG }) | Measure-Object Not_Applicable -Sum).Sum
    $cellcount++
    $count++
}

$null = $InfoWKST.UsedRange.Columns.AutoFit()
$Finding_CSV++

Write-Progress -Activity "Counting CAT III Findings" -Completed

if ($MachineInfo){
    Write-Log $LogPath "Adding Machine Info..." "Machine Info" "Info"
    $MachineInfoWKST = $workbooks.Worksheets.Item($Finding_CSV)
    $MachineInfoWKST.Name = "Machine Information"
    $MachineInfoWKST.Cells.Item(1, 8) = "Per Machine STIG Information per Evaluate-STIG"
    $MachineInfoWKST.Cells.Item(1, 8).Font.Size = 18
    $MachineInfoWKST.Range("H1:O1").MergeCells = $true
    $MachineInfoWKST.Cells.Item(4, 2) = "Scan Date"

    $MachineInfoWKST.Cells.Item(3, 4) = "CAT I"
    $MachineInfoWKST.Cells.Item(3, 4).Font.Size = 18
    $MachineInfoWKST.Cells.Item(3, 4).HorizontalAlignment = -4108
    $MachineInfoWKST.Range("D3:G3").MergeCells = $true

    $MachineInfoWKST.Cells.Item(3, 10) = "CAT II"
    $MachineInfoWKST.Cells.Item(3, 10).Font.Size = 18
    $MachineInfoWKST.Cells.Item(3, 10).HorizontalAlignment = -4108
    $MachineInfoWKST.Range("J3:M3").MergeCells = $true

    $MachineInfoWKST.Cells.Item(3, 16) = "CAT III"
    $MachineInfoWKST.Cells.Item(3, 16).Font.Size = 18
    $MachineInfoWKST.Cells.Item(3, 16).HorizontalAlignment = -4108
    $MachineInfoWKST.Range("P3:S3").MergeCells = $true

    $MachineInfoWKST.Cells.Item(4, 4) = "Open"
    $MachineInfoWKST.Cells.Item(4, 5) = "Not_Reviewed"
    $MachineInfoWKST.Cells.Item(4, 6) = "NotAFinding"
    $MachineInfoWKST.Cells.Item(4, 7) = "Not_Applicable"
    $MachineInfoWKST.Cells.Item(4, 10) = "Open"
    $MachineInfoWKST.Cells.Item(4, 11) = "Not_Reviewed"
    $MachineInfoWKST.Cells.Item(4, 12) = "NotAFinding"
    $MachineInfoWKST.Cells.Item(4, 13) = "Not_Applicable"
    $MachineInfoWKST.Cells.Item(4, 16) = "Open"
    $MachineInfoWKST.Cells.Item(4, 17) = "Not_Reviewed"
    $MachineInfoWKST.Cells.Item(4, 18) = "NotAFinding"
    $MachineInfoWKST.Cells.Item(4, 19) = "Not_Applicable"

    if ($ACAS){
        $MachineInfoWKST.Cells.Item(4, 22) = "Critical"
        $MachineInfoWKST.Cells.Item(4, 23) = "High"
        $MachineInfoWKST.Cells.Item(4, 24) = "Medium"
        $MachineInfoWKST.Cells.Item(4, 25) = "Low"
        $MachineInfoWKST.Cells.Item(4, 26) = "Info"
    }

    $cellcount = 5
    $count = 0

    Foreach ($Hostname in ($Counts_CAT_I.Hostname | Sort-Object -Unique)) {

        Write-Progress -Activity "Counting CAT I Findings for Assets" -Status $HostName -PercentComplete ($count / @($Counts_CAT_I.HostName | Select-Object -Unique).count * 100)
        Write-Log $LogPath "  Adding $Hostname CAT I Info..." "Machine Info" "Info"

        $MachineInfoWKST.Cells.Item($cellcount, 1) = $Hostname
        $MachineInfoWKST.Cells.Item($cellcount, 2) = ($Scandate | Where-Object { $_.Hostname -eq $Hostname }).ScanDate
        $MachineInfoWKST.Cells.Item($cellcount, 4) = (($Counts_CAT_I | Where-Object { $_.Hostname -eq $Hostname }) | Measure-Object Open -Sum).Sum
        $MachineInfoWKST.Cells.Item($cellcount, 5) = (($Counts_CAT_I | Where-Object { $_.Hostname -eq $Hostname }) | Measure-Object Not_Reviewed -Sum).Sum
        $MachineInfoWKST.Cells.Item($cellcount, 6) = (($Counts_CAT_I | Where-Object { $_.Hostname -eq $Hostname }) | Measure-Object NotAFinding -Sum).Sum
        $MachineInfoWKST.Cells.Item($cellcount, 7) = (($Counts_CAT_I | Where-Object { $_.Hostname -eq $Hostname }) | Measure-Object Not_Applicable -Sum).Sum
        if ($ACAS) {
            $MachineInfoWKST.Cells.Item($cellcount, 22) = ($ACAS_CSV | Where-Object { $_.'DNS Name' -match $Hostname }).'Crit.'
            $MachineInfoWKST.Cells.Item($cellcount, 23) = ($ACAS_CSV | Where-Object { $_.'DNS Name' -match $Hostname }).High
            $MachineInfoWKST.Cells.Item($cellcount, 24) = ($ACAS_CSV | Where-Object { $_.'DNS Name' -match $Hostname }).'Med.'
            $MachineInfoWKST.Cells.Item($cellcount, 25) = ($ACAS_CSV | Where-Object { $_.'DNS Name' -match $Hostname }).Low
            $MachineInfoWKST.Cells.Item($cellcount, 26) = ($ACAS_CSV | Where-Object { $_.'DNS Name' -match $Hostname }).Info
        }
        $cellcount++
        $count++
    }

    Write-Progress -Activity "Counting CAT I Findings for Assets" -Completed

    $cellcount = 5
    $count = 0

    Foreach ($Hostname in ($Counts_CAT_II.Hostname | Sort-Object -Unique)) {

        Write-Progress -Activity "Counting CAT II Findings for Assets" -Status $HostName -PercentComplete ($count / @($Counts_CAT_II.HostName | Select-Object -Unique).count * 100)
        Write-Log $LogPath "  Adding $Hostname CAT II Info..." "Machine Info" "Info"

        $MachineInfoWKST.Cells.Item($cellcount, 10) = (($Counts_CAT_II | Where-Object { $_.Hostname -eq $Hostname }) | Measure-Object Open -Sum).Sum
        $MachineInfoWKST.Cells.Item($cellcount, 11) = (($Counts_CAT_II | Where-Object { $_.Hostname -eq $Hostname }) | Measure-Object Not_Reviewed -Sum).Sum
        $MachineInfoWKST.Cells.Item($cellcount, 12) = (($Counts_CAT_II | Where-Object { $_.Hostname -eq $Hostname }) | Measure-Object NotAFinding -Sum).Sum
        $MachineInfoWKST.Cells.Item($cellcount, 13) = (($Counts_CAT_II | Where-Object { $_.Hostname -eq $Hostname }) | Measure-Object Not_Applicable -Sum).Sum
        $cellcount++
        $count++
    }

    Write-Progress -Activity "Counting CAT II Findings for Assets" -Completed

    $cellcount = 5
    $count = 0

    Foreach ($Hostname in ($Counts_CAT_III.Hostname | Sort-Object -Unique)) {

        Write-Progress -Activity "Counting CAT III Findings for Assets" -Status $HostName -PercentComplete ($count / @($Counts_CAT_III.HostName | Select-Object -Unique).count * 100)
        Write-Log $LogPath "  Adding $Hostname CAT III Info..." "Machine Info" "Info"

        $MachineInfoWKST.Cells.Item($cellcount, 16) = (($Counts_CAT_III | Where-Object { $_.Hostname -eq $Hostname }) | Measure-Object Open -Sum).Sum
        $MachineInfoWKST.Cells.Item($cellcount, 17) = (($Counts_CAT_III | Where-Object { $_.Hostname -eq $Hostname }) | Measure-Object Not_Reviewed -Sum).Sum
        $MachineInfoWKST.Cells.Item($cellcount, 18) = (($Counts_CAT_III | Where-Object { $_.Hostname -eq $Hostname }) | Measure-Object NotAFinding -Sum).Sum
        $MachineInfoWKST.Cells.Item($cellcount, 19) = (($Counts_CAT_III | Where-Object { $_.Hostname -eq $Hostname }) | Measure-Object Not_Applicable -Sum).Sum
        $cellcount++
        $count++
    }

    Write-Progress -Activity "Counting CAT III Findings for Assets" -Completed
    $null = $MachineInfoWKST.UsedRange.Columns.AutoFit()
    $Finding_CSV++
}

Write-Host "Combining CKL Finding data to Excel spreadsheet."
Write-Log $LogPath "Combining CKL Finding data to Excel spreadsheet." "Excel" "Info"

if ($STIGInfo){
    forEach ($Finding in $Findings_List) {
        $WorkSheet_Name = $Finding.replace([System.IO.Path]::GetTempPath(), "").replace(".csv", "")
        $WorkSheet_Name = $WorkSheet_Name.Substring(0, [System.Math]::Min(31, $WorkSheet_Name.Length))
        $worksheet = $workbooks.Worksheets.Item($Finding_CSV)
        $sheet = $workbooks.worksheets | Where-Object {$_.Name -eq $WorkSheet_Name}
        if (!($sheet)){
            $worksheet.Name = $WorkSheet_Name
        }
        $TxtConnector = ("TEXT;" + $Finding)
        $Cellref = $Worksheet.Range("A1")
        $Connector = $worksheet.QueryTables.add($TxtConnector,$Cellref)
        $worksheet.QueryTables.item($Connector.name).TextFileCommaDelimiter = $true
        $worksheet.QueryTables.item($Connector.name).TextFileParseType = 1
        $null = $worksheet.QueryTables.item($Connector.name).Refresh()
        $null = $worksheet.QueryTables.item($Connector.name).delete()
        $null = $worksheet.UsedRange.EntireColumn.AutoFit()
        $Finding_CSV++
    }

    $Findings_List | ForEach-Object {Remove-Item $_ -Force}
}

Try {
    $workbooks.SaveAs("$(join-path $OutPutpath -ChildPath $Report_Name)", 51)
    Write-Host "Combined excel spreadsheet saved as $(Join-Path $OutPutpath -ChildPath $Report_Name)"
    Write-Host "Log saved as $LogPath"
    Write-Log $LogPath "Combined excel spreadsheet saved as $(Join-Path $OutPutpath -ChildPath $Report_Name)" "Finish" "Info"
}
Catch{
    $workbooks.SaveAs("$(Join-Path $PSScriptRoot -ChildPath $Report_Name)", 51)
    Write-Host "$OutputPath was not accessible.  Saving to script directory."
    Write-Host "Combined excel spreadsheet saved as $(Join-Path $PSScriptRoot -ChildPath $Report_Name)"
    Write-Host "Log saved as $LogPath"
    Write-Log $LogPath "$OutputPath was not accessible.  Saving to script directory." "Finish" "Info"
    Write-Log $LogPath "Combined excel spreadsheet saved as $(Join-Path $PSScriptRoot -ChildPath $Report_Name)" "Finish" "Info"
}

$workbooks.Close()
$null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($workbooks)
Write-Log $LogPath "==========[End Logging]==========" "Finish" "Info"

# SIG # Begin signature block
# MIIL1AYJKoZIhvcNAQcCoIILxTCCC8ECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUJu9PftGWnmyboI+WWLraYYHx
# bxigggk7MIIEejCCA2KgAwIBAgIEAwIE1zANBgkqhkiG9w0BAQsFADBaMQswCQYD
# VQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0Qx
# DDAKBgNVBAsTA1BLSTEVMBMGA1UEAxMMRE9EIElEIENBLTU5MB4XDTIwMDcxNTAw
# MDAwMFoXDTI1MDQwMjEzMzgzMlowaTELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1Uu
# Uy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMQwwCgYDVQQLEwNQS0kxDDAKBgNV
# BAsTA1VTTjEWMBQGA1UEAxMNQ1MuTlNXQ0NELjAwMTCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBANv2fdTmx2dNPQ47F8kmvU+g20/sFoF+DS3k2GcMduuI
# XxYFJyMMPAvTJuobeJlX6P6sr5jAKhXXsoV4lT2boWw583Snl6cuSfqMbVowIJ1s
# CffN7N0VXsLVdOt1u5GCKs4/jXH7MeEOE0oJsgEjjE1IZc5tEqj++s1N1EUY+jf/
# zc8QHDjy5X88XBTzKVhwvczZVbRahrcmYv0k4we3ndwTl5nXYizSwi96CZuqzrIn
# WbLSsRLNyNZZVo7J5bZ+30dv/hZvq6FqxfAeM3pEDrvbfFkWXzaISqF1bVbsMlAC
# UBf/JFbSGtmMsU1ABfXKPalTWYJKP58dICHcUocZhL0CAwEAAaOCATcwggEzMB8G
# A1UdIwQYMBaAFHUJphUTroc8+nOUAPLw9Xm5snIUMEEGA1UdHwQ6MDgwNqA0oDKG
# MGh0dHA6Ly9jcmwuZGlzYS5taWwvY3JsL0RPRElEQ0FfNTlfTkNPREVTSUdOLmNy
# bDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0gBA8wDTALBglghkgBZQIBCyowHQYDVR0O
# BBYEFFbrF3OpzfdsZkN1zTfv++oaLCRRMGUGCCsGAQUFBwEBBFkwVzAzBggrBgEF
# BQcwAoYnaHR0cDovL2NybC5kaXNhLm1pbC9zaWduL0RPRElEQ0FfNTkuY2VyMCAG
# CCsGAQUFBzABhhRodHRwOi8vb2NzcC5kaXNhLm1pbDAfBgNVHSUEGDAWBgorBgEE
# AYI3CgMNBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOCAQEAQknaIAXDnyqshmyh
# uOZS4nBtSydnZrdB8Je0JCq2TTRA4dkNvrswe0kZgA7UjlY1X/9PtQeIwaMrcvdF
# i+dqzD1bbW/LX5tH/1oMOp4s+VkGfl4xUUxUGjO6QTVOeLyN2x+DBQU11DhKEq9B
# RCxUGgclFn1iqxi5xKmLaQ3XuRWRGCkb+rXejWR+5uSTognxCuoLp95bqu3JL8ec
# yF46+VSoafktAGot2Uf3qmwWdMHFBdwzmJalbC4j09I1qJqcJH0p8Wt34zRw/hSr
# 3f+xDEDP8GNL2ciDm7aN0GKy67ugjgMmPXAv7A4/keCuN/dsNS1naNyqzc5AhTAF
# +o/21jCCBLkwggOhoAMCAQICAgMFMA0GCSqGSIb3DQEBCwUAMFsxCzAJBgNVBAYT
# AlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoG
# A1UECxMDUEtJMRYwFAYDVQQDEw1Eb0QgUm9vdCBDQSAzMB4XDTE5MDQwMjEzMzgz
# MloXDTI1MDQwMjEzMzgzMlowWjELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4g
# R292ZXJubWVudDEMMAoGA1UECxMDRG9EMQwwCgYDVQQLEwNQS0kxFTATBgNVBAMT
# DERPRCBJRCBDQS01OTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMwX
# hJ8twQpXrRFNNVc/JEcvHA9jlr27cDE8rpxWkobvpCJOoOVUbJ724Stx6OtTAZpR
# iXNaS0jjRgYaW6cq9pdnjjQM5ovHPPde1ewaZyWb2I+uqhkZmOBV1+lGUOhnQCyi
# nnSSqzEH1PC5nASfyxnCdBeOt+UKHBrPVKBUuYS4Fcn5Q0wv+sfBD24vyV5Ojeoq
# HeSSAMTaeqlv+WQb4YrjKNfaGF+S7lMvQelu3ANHEcoL2HMCimCvnCHQaMQI9+Ms
# NhySPEULePdEDxgpWYc9FmBbjUp1CYEx7HYdlTRJ9gBHts2ITxTZQrt4Epjkqeb8
# aWVmzCEPHE7+KUVhuO8CAwEAAaOCAYYwggGCMB8GA1UdIwQYMBaAFGyKlKJ3sYBy
# HYF6Fqry3M5m7kXAMB0GA1UdDgQWBBR1CaYVE66HPPpzlADy8PV5ubJyFDAOBgNV
# HQ8BAf8EBAMCAYYwZwYDVR0gBGAwXjALBglghkgBZQIBCyQwCwYJYIZIAWUCAQsn
# MAsGCWCGSAFlAgELKjALBglghkgBZQIBCzswDAYKYIZIAWUDAgEDDTAMBgpghkgB
# ZQMCAQMRMAwGCmCGSAFlAwIBAycwEgYDVR0TAQH/BAgwBgEB/wIBADAMBgNVHSQE
# BTADgAEAMDcGA1UdHwQwMC4wLKAqoCiGJmh0dHA6Ly9jcmwuZGlzYS5taWwvY3Js
# L0RPRFJPT1RDQTMuY3JsMGwGCCsGAQUFBwEBBGAwXjA6BggrBgEFBQcwAoYuaHR0
# cDovL2NybC5kaXNhLm1pbC9pc3N1ZWR0by9ET0RST09UQ0EzX0lULnA3YzAgBggr
# BgEFBQcwAYYUaHR0cDovL29jc3AuZGlzYS5taWwwDQYJKoZIhvcNAQELBQADggEB
# ADkFG9IOpz71qHNXCeYJIcUshgN20CrvB5ym4Pr7zKTBRMKNqd9EXWBxrwP9xhra
# 5YcQagHDqnmBeU3F2ePhWvQmyhPwIJaArk4xGLdv9Imkr3cO8vVapO48k/R9ZRSA
# EBxzd0xMDdZ6+xxFlZJIONRlxcVNNVB30e74Kk08/t82S9ogqgA1Q7KZ2tFuaRes
# jJWuoJ+LtE5lrtknqgaXLb3XH0hV5M0AWRk9Wg/1thb9NCsKEIAdpdnolZOephIz
# fzHiOSqeJ+e5qURLB7rT+F5y0NNWTdqoJ/vOOCUa8z0NKWsz2IkpeD3iNhVCLRKw
# Ojm/wzxdG2tst5OHRZFEwKcxggIDMIIB/wIBATBiMFoxCzAJBgNVBAYTAlVTMRgw
# FgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMD
# UEtJMRUwEwYDVQQDEwxET0QgSUQgQ0EtNTkCBAMCBNcwCQYFKw4DAhoFAKB4MBgG
# CisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcC
# AQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYE
# FBdLvHxhoyuAmoMxL9VM65NOljflMA0GCSqGSIb3DQEBAQUABIIBAMUkLmQSTlJV
# ifTkpC85qJQ1MkkitAgZFHPDxf1BehluhFZAtwxNl3cboGoI9K3ozvoGrMgliFTU
# FelX89dSyglWlzmnw5KRVcCFrxaTizklp6nFTI5cGE03X62Cjoq3myr6BG3qaW3M
# D8PJVQ+x7BRbviCSUsgwxK5jJ3oo7IWxw2NTL1uXG2NhY5GN4oa39HCbUVznrep8
# 9l1gVkrm3nE11HQkvPeSuHR50ZPHZ5vLTiZl3g1+y8FqoOhfk/66y4YzUxKBoD0p
# sn8yVyFNiRu+GI6/cZNr/3vXpGHIJI2Ce6MhnJin647V9cNFeJE7uuRAZFWzVeWP
# dMJ4tZn88y4=
# SIG # End signature block
